pub use platypus_apk as apk;
pub use platypus_dex as dex;
pub use platypus_vm as vm;
pub use platypus_codegen as codegen;
pub use platypus_resources as resources;
pub use platypus_rehydrate as rehydrate;
pub use platypus_license as license;

pub mod analysis;
pub mod taint;
pub mod dex_loader_analysis;

#[cfg(feature = "python")]
mod python;

#[cfg(feature = "python")]
pub use python::platypus;
