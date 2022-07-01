use core::mem::{self, MaybeUninit};
use core::ptr;
use core::slice;
use cryptographic_message_syntax::SignedData;
use digest::{Digest, Mac};
use rand::Rng;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{PublicKey, RsaPublicKey};
use scopeguard::defer;
use thiserror::Error;
use x509_certificate::KeyAlgorithm;

use windows::Win32::Foundation::{BOOL, LPARAM, RECT};
use windows::Win32::Graphics::Direct3D9::{
    Direct3DCreate9, D3DADAPTER_DEFAULT, D3DCAPS9, D3DDEVTYPE_HAL, D3D_SDK_VERSION,
};
use windows::Win32::Graphics::Gdi::{EnumDisplayMonitors, HDC, HMONITOR};
use windows::Win32::Media::MediaFoundation::{
    OPMGetVideoOutputsFromHMONITOR, OPM_ENCRYPTED_INITIALIZATION_PARAMETERS,
    OPM_GET_CONNECTOR_TYPE, OPM_GET_INFO_PARAMETERS, OPM_OMAC_SIZE, OPM_STANDARD_INFORMATION,
    OPM_STATUS_NORMAL, OPM_VOS_OPM_SEMANTICS,
};
use windows::Win32::System::Com::CoTaskMemFree;

const MICROSOFT_MEDIA_AUTHORITY_PUBKEY_SHA256: [u8; 32] =
    hex_literal::hex!("d397f5c155034953909f29d840856abf83563eed9cba6e0b6f7f8541a020556d");

type Cmac = cmac::Cmac<aes::Aes128>;

#[derive(Error, Debug)]
pub enum PlatformCheckError {
    #[error("Direct3D 9 not supported")]
    NoDirect3D9,
    #[error("Software renderer detected")]
    SoftwareRenderer,
    #[error("Virtual GPU detected")]
    VirtualGPUDetected,
    #[error("CMS error: {0}")]
    CMSError(#[from] cryptographic_message_syntax::CmsError),
    #[error("Windows error: {0}")]
    WindowsError(#[from] windows::core::Error),
    #[error("RSA error: {0}")]
    RSAError(#[from] rsa::errors::Error),
    #[error("PKCS #1 error: {0}")]
    PKCS1Error(#[from] rsa::pkcs1::Error),
    #[error("OPM error: Invalid OPM root certificate")]
    OPMRootInvalid,
    #[error("OPM error: OPM OMAC validation failed")]
    OPMOMACInvalid,
    #[error("OPM error: Nonce mismatch")]
    OPMNonceMismatch,
    #[error("OPM error: Invalid certificate format")]
    OPMInvalidCertificate,
    #[error("OPM error: No available outputs")]
    OPMNoOutputs,
    #[error("OPM error: Anomaly detected")]
    OPMStatusAbnormal,
    #[error("No display detected")]
    NoDisplay,
}

extern "system" fn enum_monitors_cb(
    monitor: HMONITOR,
    _devcontext: HDC,
    _rect: *mut RECT,
    LPARAM(data): LPARAM,
) -> BOOL {
    eprintln!(
        "GDI: EnumDisplayMonitors callback: Got monitor 0x{:08x}",
        monitor.0
    );
    let vec = unsafe { &mut *(data as usize as *mut Vec<HMONITOR>) };
    vec.push(monitor);
    BOOL::from(true)
}

pub fn should_run() -> Result<(), PlatformCheckError> {
    let mut rng = rand::thread_rng();

    let direct3d =
        unsafe { Direct3DCreate9(D3D_SDK_VERSION).ok_or(PlatformCheckError::NoDirect3D9)? };

    let mut caps: MaybeUninit<D3DCAPS9> = MaybeUninit::uninit();
    unsafe {
        direct3d.GetDeviceCaps(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, caps.as_mut_ptr())?;
    }

    let mut ident = MaybeUninit::uninit();
    unsafe {
        direct3d.GetAdapterIdentifier(D3DADAPTER_DEFAULT, 0, ident.as_mut_ptr())?;
    }
    let ident = unsafe { ident.assume_init() };

    eprintln!(
        "DirectX: Detected vendorId={:04x} deviceId={:04x}",
        ident.VendorId, ident.DeviceId
    );

    match (ident.VendorId, ident.DeviceId) {
        (0x1414, 0x008c) // Microsoft Basic Render Device
        => return Err(PlatformCheckError::SoftwareRenderer),
        | (0x15ad, 0x0405) // VMware
        | (0x80ee, 0xbeef) // VirtualBox
        | (0x1ab8, 0x4005) // Parallels
        | (0x1af4, 0x1050) // Virtio GPU
        | (0x1414, 0x5353) // Hyper-V
        => return Err(PlatformCheckError::VirtualGPUDetected),
        _ => (),
    }

    let mut monitors: Vec<HMONITOR> = Vec::new();
    eprintln!("GDI: EnumDisplayMonitors");
    unsafe {
        EnumDisplayMonitors(
            HDC(0),
            ptr::null(),
            Some(enum_monitors_cb),
            LPARAM(&mut monitors as *mut _ as usize as isize),
        );
    }

    let monitor = monitors.first().ok_or(PlatformCheckError::NoDisplay)?;

    let mut opm_output_count = MaybeUninit::uninit();
    let mut opm_outputs = MaybeUninit::uninit();
    eprintln!("OPM: OPMGetVideoOutputsFromHMONITOR");
    unsafe {
        OPMGetVideoOutputsFromHMONITOR(
            monitor,
            OPM_VOS_OPM_SEMANTICS,
            opm_output_count.as_mut_ptr(),
            opm_outputs.as_mut_ptr(),
        )?;
    }
    let opm_output_count = unsafe { opm_output_count.assume_init() } as usize;
    let opm_outputs = unsafe { opm_outputs.assume_init() };
    defer! { unsafe { CoTaskMemFree(opm_outputs as *mut _) } }

    let mut opm_outputs_vec = Vec::with_capacity(opm_output_count);
    for i in 0..opm_output_count {
        let owned = unsafe { ptr::read(opm_outputs.offset(i as isize)) };
        if let Some(owned) = owned {
            opm_outputs_vec.push(owned)
        }
    }

    let chosen_opm_output = opm_outputs_vec
        .first()
        .ok_or(PlatformCheckError::OPMNoOutputs)?;

    let mut opm_rand = MaybeUninit::uninit();
    let mut opm_cert = MaybeUninit::uninit();
    let mut opm_cert_len = MaybeUninit::uninit();
    eprintln!("OPM: StartInitialization");
    unsafe {
        chosen_opm_output.StartInitialization(
            opm_rand.as_mut_ptr(),
            opm_cert.as_mut_ptr(),
            opm_cert_len.as_mut_ptr(),
        )?;
    }
    let opm_rand = unsafe { opm_rand.assume_init() };
    let opm_cert_raw = unsafe { opm_cert.assume_init() };
    let opm_cert_len = unsafe { opm_cert_len.assume_init() } as usize;
    let opm_cert = unsafe { slice::from_raw_parts(opm_cert_raw, opm_cert_len) };
    defer! { unsafe { CoTaskMemFree(opm_cert_raw as *mut _) } }

    let p7 = SignedData::parse_ber(opm_cert)?;
    eprintln!("OPM: Finding end entity certificate");
    let driver_cert = p7
        .certificates()
        .find(|c| {
            p7.certificates()
                .find(|d| d.issuer_name() == c.subject_name())
                .is_none()
        })
        .ok_or(PlatformCheckError::OPMInvalidCertificate)?;

    eprintln!("OPM: Finding root certificate");
    let cert_chain = driver_cert.resolve_signing_chain(p7.certificates());
    let root_cert = cert_chain
        .into_iter()
        .last()
        .ok_or(PlatformCheckError::OPMInvalidCertificate)?;

    if root_cert.key_algorithm() != Some(KeyAlgorithm::Rsa) {
        return Err(PlatformCheckError::OPMInvalidCertificate);
    }

    if sha2::Sha256::digest(&root_cert.public_key_data()).as_slice()
        != &MICROSOFT_MEDIA_AUTHORITY_PUBKEY_SHA256[..]
    {
        return Err(PlatformCheckError::OPMRootInvalid);
    }

    if driver_cert.key_algorithm() != Some(KeyAlgorithm::Rsa) {
        return Err(PlatformCheckError::OPMInvalidCertificate);
    }

    let public_key = driver_cert.public_key_data();
    let public_key = RsaPublicKey::from_pkcs1_der(&public_key[..])?;

    let seq_status: u32 = rng.gen();
    let seq_command: u32 = rng.gen();

    let mut session_key = digest::Key::<Cmac>::default();
    rng.fill(&mut session_key[..]);

    let mut enc_params_internal = Vec::new();
    enc_params_internal.extend_from_slice(&opm_rand.abRandomNumber[..]);
    enc_params_internal.extend_from_slice(&session_key[..]);
    enc_params_internal.extend_from_slice(&seq_status.to_ne_bytes());
    enc_params_internal.extend_from_slice(&seq_command.to_ne_bytes());

    let padding = rsa::PaddingScheme::new_oaep::<sha2::Sha512>();
    let enc_params_internal = public_key.encrypt(&mut rng, padding, &enc_params_internal)?;

    let mut enc_params = OPM_ENCRYPTED_INITIALIZATION_PARAMETERS {
        abEncryptedInitializationParameters: [0; 256],
    };
    enc_params.abEncryptedInitializationParameters[..enc_params_internal.len()]
        .copy_from_slice(&enc_params_internal);

    eprintln!("OPM: FinishInitialization");
    unsafe {
        chosen_opm_output.FinishInitialization(&enc_params)?;
    }

    let mut omac = Cmac::new(&session_key);
    let omac_size = OPM_OMAC_SIZE.0 as usize;

    let mut opm_request = unsafe { mem::zeroed::<OPM_GET_INFO_PARAMETERS>() };
    rng.fill(&mut opm_request.rnRandomNumber.abRandomNumber[..]);
    opm_request.ulSequenceNumber = seq_status;
    opm_request.guidInformation = OPM_GET_CONNECTOR_TYPE;

    omac.update(&raw_of(&opm_request)[omac_size..]);
    let omac_sig = omac.finalize_reset();
    opm_request.omac.abOMAC[..].copy_from_slice(&omac_sig.into_bytes());

    eprintln!("OPM: GetInformation");
    let opm_result = unsafe { chosen_opm_output.GetInformation(&opm_request)? };

    omac.update(&raw_of(&opm_result)[omac_size..]);
    let omac_res_sig = omac.finalize_reset();
    if omac_res_sig != digest::CtOutput::from(aes::Block::from(opm_result.omac.abOMAC)) {
        return Err(PlatformCheckError::OPMOMACInvalid);
    }

    let opm_resp = unsafe {
        ptr::read_unaligned::<OPM_STANDARD_INFORMATION>(
            opm_result.abRequestedInformation.as_ptr() as *const _
        )
    };
    if opm_resp.rnRandomNumber.abRandomNumber != opm_request.rnRandomNumber.abRandomNumber {
        return Err(PlatformCheckError::OPMNonceMismatch);
    }
    if opm_resp.ulStatusFlags != OPM_STATUS_NORMAL.0 as u32 {
        return Err(PlatformCheckError::OPMStatusAbnormal);
    }

    Ok(())
}

fn raw_of<T>(data: &T) -> &[u8] {
    unsafe { slice::from_raw_parts(data as *const _ as *const u8, mem::size_of::<T>()) }
}
