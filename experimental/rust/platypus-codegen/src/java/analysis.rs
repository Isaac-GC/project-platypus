/// Analysis configuration — translates codegen/java/analysis.py

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisPass {
    DeadCode,
    Deobfuscation,
    UnicodeRecovery,
}

#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub enable_deobfuscation:    bool,
    pub enable_unicode_recovery: bool,
    pub enable_dead_code:        bool,
    /// "z", "reachability", or "both"
    pub dead_code_algorithm:     String,
    /// 1 = safe, 2 = aggressive, 3 = speculative
    pub deobfuscation_level:     u8,
    /// "unicode", "escaped", or "both"
    pub unicode_display:         String,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        AnalysisConfig {
            enable_deobfuscation:    true,
            enable_unicode_recovery: true,
            enable_dead_code:        true,
            dead_code_algorithm:     "z".to_string(),
            deobfuscation_level:     2,
            unicode_display:         "both".to_string(),
        }
    }
}
