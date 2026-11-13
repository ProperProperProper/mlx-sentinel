use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct KvStats { pub mean_norm: f64, pub max_norm: f64, pub attention_entropy: Option<f64> }

#[derive(Debug, Clone, Serialize)]
pub struct Decision { pub allowed: bool, pub score: f64, pub action: String, pub reasons: Vec<String> }

pub fn inspect(stats: &KvStats, enforce: bool) -> Decision {
    let mut score: f64 = 0.0;
    let mut reasons = Vec::new();
    if !stats.mean_norm.is_finite() || !stats.max_norm.is_finite() { score += 0.8; reasons.push("invalid-kv-norm".into()); }
    if stats.max_norm > 100.0 { score += 0.3; reasons.push("kv-max-norm-outlier".into()); }
    if stats.attention_entropy.is_some_and(|v| !v.is_finite()) { score += 0.8; reasons.push("invalid-attention-entropy".into()); }
    let allowed = !enforce || score < 0.75 && reasons.is_empty();
    Decision { allowed, score: score.min(1.0), action: if allowed { "allow" } else { "block" }.into(), reasons: if reasons.is_empty() { vec!["normal-behavior".into()] } else { reasons } }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn normal_is_allowed() { assert!(inspect(&KvStats { mean_norm: 1.0, max_norm: 2.0, attention_entropy: None }, true).allowed); }
    #[test] fn outlier_is_blocked() { assert!(!inspect(&KvStats { mean_norm: 1.0, max_norm: 101.0, attention_entropy: None }, true).allowed); }
}
