//! DUAL record decoder (ADR 0031 section 4), a read-only port of the omega
//! C checker and codec in `src/dual/rx_dual.c` on omega branch
//! `dual/0a-records`, commit f056b77f64ee94a80f4ed2899b5f9495aa3ef840.
//!
//! Every enum value, field order, refusal and digest domain below is copied
//! from that commit's `rx_dual.h` / `rx_dual.c`. Encodings start with
//! `u8 kind, u8 version(1)`, integers are little-endian, doubles are IEEE-754
//! binary64 bits with `-0.0` written as `+0.0`, digests are 32 bytes.
//! Digest = SHA-256(domain || 0x00 || canonical encoding).
//!
//! This module only reads. It mints nothing, authorizes nothing and is never
//! consulted by a gate. A price is scarcity information, not permission.

use sha2::{Digest as _, Sha256};

pub const DIGEST_SIZE: usize = 32;
pub const FORMAT_VERSION: u8 = 1;
pub const MAX_RESOURCES: u32 = 32;

pub const DOMAIN_RESOURCE: &str = "omega.dual.resource.v1";
pub const DOMAIN_CONSTRAINT: &str = "omega.dual.constraint.v1";
pub const DOMAIN_CONTROLLER: &str = "omega.dual.controller.v1";
pub const DOMAIN_PRICE_VECTOR: &str = "omega.dual.pricevec.v1";

/// 32-byte digest. All-zero means absent.
pub type Digest32 = [u8; DIGEST_SIZE];

pub fn digest_is_zero(d: &Digest32) -> bool {
    d.iter().all(|b| *b == 0)
}

/// SHA-256(domain || 0x00 || encoding), the DUAL identity rule.
pub fn domain_digest(domain: &str, encoding: &[u8]) -> Digest32 {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(encoding);
    h.finalize().into()
}

/// Record kind bytes (`RxDualKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Resource = 1,
    Constraint = 2,
    Controller = 3,
    PriceVector = 4,
}

/// Closed unit registry (`RxDualUnit`). `NONE` (0) and anything >= 16 are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum Unit {
    Ps = 1,
    Pj = 2,
    Bytes = 3,
    BytesPerS = 4,
    KvBlocks = 5,
    PpmOccupancy = 6,
    NsVerify = 7,
    NsSynth = 8,
    Ns = 9,
    Watt = 10,
    WattPerS = 11,
    MilliCelsius = 12,
    MilliCelsiusPerS = 13,
    Dimensionless = 14,
    Log2Ps = 15,
}

impl Unit {
    pub fn from_u32(v: u32) -> Option<Unit> {
        Some(match v {
            1 => Unit::Ps,
            2 => Unit::Pj,
            3 => Unit::Bytes,
            4 => Unit::BytesPerS,
            5 => Unit::KvBlocks,
            6 => Unit::PpmOccupancy,
            7 => Unit::NsVerify,
            8 => Unit::NsSynth,
            9 => Unit::Ns,
            10 => Unit::Watt,
            11 => Unit::WattPerS,
            12 => Unit::MilliCelsius,
            13 => Unit::MilliCelsiusPerS,
            14 => Unit::Dimensionless,
            15 => Unit::Log2Ps,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Unit::Ps => "PS",
            Unit::Pj => "PJ",
            Unit::Bytes => "BYTES",
            Unit::BytesPerS => "BYTES_PER_S",
            Unit::KvBlocks => "KV_BLOCKS",
            Unit::PpmOccupancy => "PPM_OCCUPANCY",
            Unit::NsVerify => "NS_VERIFY",
            Unit::NsSynth => "NS_SYNTH",
            Unit::Ns => "NS",
            Unit::Watt => "WATT",
            Unit::WattPerS => "WATT_PER_S",
            Unit::MilliCelsius => "MILLI_CELSIUS",
            Unit::MilliCelsiusPerS => "MILLI_CELSIUS_PER_S",
            Unit::Dimensionless => "DIMENSIONLESS",
            Unit::Log2Ps => "LOG2_PS",
        }
    }
}

/// Constraint class (`RxDualClass`). Only CAPACITY and SOFT construct;
/// UNDECLARED (0) and INVARIANT (1) are refused, never defaulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum Class {
    /// Diagnostic lambda only; never relaxed.
    Capacity = 2,
    /// Priceable.
    Soft = 3,
}

impl Class {
    pub fn from_u32(v: u32) -> Option<Class> {
        match v {
            2 => Some(Class::Capacity),
            3 => Some(Class::Soft),
            _ => None,
        }
    }
}

/// `RxDualEstimateKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum EstimateKind {
    Measured = 1,
    Estimated = 2,
    Predicted = 3,
}

impl EstimateKind {
    pub fn from_u32(v: u32) -> Option<EstimateKind> {
        match v {
            1 => Some(EstimateKind::Measured),
            2 => Some(EstimateKind::Estimated),
            3 => Some(EstimateKind::Predicted),
            _ => None,
        }
    }
}

/// `RxDualLambdaState`. Consumers treat everything but FRESH as absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum LambdaState {
    Fresh = 1,
    Stale = 2,
    Frozen = 3,
    Uncalibrated = 4,
    Refused = 5,
}

impl LambdaState {
    pub fn from_u32(v: u32) -> Option<LambdaState> {
        match v {
            1 => Some(LambdaState::Fresh),
            2 => Some(LambdaState::Stale),
            3 => Some(LambdaState::Frozen),
            4 => Some(LambdaState::Uncalibrated),
            5 => Some(LambdaState::Refused),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            LambdaState::Fresh => "FRESH",
            LambdaState::Stale => "STALE",
            LambdaState::Frozen => "FROZEN",
            LambdaState::Uncalibrated => "UNCALIBRATED",
            LambdaState::Refused => "REFUSED",
        }
    }
}

/// Refusal reasons, one per `RxDualStatus` code the decoders can return.
/// `c_status()` gives the C code so golden statuses can be compared exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// NaN or Inf anywhere (-2).
    NonFinite,
    /// Missing, unknown unit (-3).
    Unit,
    /// Undeclared, INVARIANT or unknown class (-4).
    Class,
    /// Scale not strictly positive (-5).
    Scale,
    /// Negative uncertainty/lambda, bad enum, bad count (-6).
    Range,
    /// Wrong record kind byte or bad estimate kind (-7).
    Kind,
    /// Truncated, trailing bytes, bad version (-8).
    Encoding,
    /// Duplicate or unordered resource id (-9).
    Resource,
    /// Required digest absent, or parent/tick linkage broken (-10).
    Digest,
    /// Generation inconsistent across a vector (-11).
    Generation,
    /// FRESH claimed without a calibration receipt (-17).
    Calibration,
}

impl Refusal {
    pub fn c_status(self) -> i32 {
        match self {
            Refusal::NonFinite => -2,
            Refusal::Unit => -3,
            Refusal::Class => -4,
            Refusal::Scale => -5,
            Refusal::Range => -6,
            Refusal::Kind => -7,
            Refusal::Encoding => -8,
            Refusal::Resource => -9,
            Refusal::Digest => -10,
            Refusal::Generation => -11,
            Refusal::Calibration => -17,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} (RxDualStatus {})", self, self.c_status())
    }
}

/// `RxDualResource` (4.1 registry entry).
#[derive(Debug, Clone, PartialEq)]
pub struct Resource {
    pub resource_id: u32,
    pub unit: Unit,
    pub scale: f64,
    pub contract: Digest32,
}

/// `RxDualConstraintState` (4.2).
#[derive(Debug, Clone, PartialEq)]
pub struct ConstraintState {
    pub resource_id: u32,
    pub unit: Unit,
    pub class: Class,
    pub budget: f64,
    pub budget_contract: Digest32,
    pub observation_ref: Digest32,
    pub estimate_ref: Digest32,
    pub estimate_kind: EstimateKind,
    pub estimate: f64,
    pub uncertainty: f64,
    pub calibration_ref: Digest32,
    pub lambda: f64,
    pub lambda_state: LambdaState,
    pub controller_id: Digest32,
    pub generation: u64,
    pub tick: u64,
    pub evidence_root: Digest32,
    pub parent: Digest32,
}

impl ConstraintState {
    /// FRESH and carrying a calibration receipt. The checker already refuses
    /// FRESH without one; this is the consumer-side restatement.
    pub fn is_fresh_calibrated(&self) -> bool {
        self.lambda_state == LambdaState::Fresh && !digest_is_zero(&self.calibration_ref)
    }
}

/// `RxDualController` (section 5.1); its digest is `controller_id`.
#[derive(Debug, Clone, PartialEq)]
pub struct Controller {
    pub eta: f64,
    pub rho: f64,
    pub k_sigma: f64,
    pub max_age: u64,
    pub cadence: u64,
    /// (resource_id, lambda_max), strictly ascending ids.
    pub entries: Vec<(u32, f64)>,
}

/// `RxDualPriceVector` (4.3): one decision context, one generation.
#[derive(Debug, Clone, PartialEq)]
pub struct PriceVector {
    pub generation: u64,
    pub context: Digest32,
    /// (resource_id, constraint state digest), strictly ascending ids.
    pub entries: Vec<(u32, Digest32)>,
}

// ---------------------------------------------------------------- reader

struct Reader<'a> {
    p: &'a [u8],
    pos: usize,
    st: Option<Refusal>,
}

impl<'a> Reader<'a> {
    fn new(p: &'a [u8]) -> Self {
        Reader {
            p,
            pos: 0,
            st: None,
        }
    }
    fn fail(&mut self, r: Refusal) {
        if self.st.is_none() {
            self.st = Some(r);
        }
    }
    fn need(&mut self, n: usize) -> bool {
        if self.st.is_some() {
            return false;
        }
        if self.pos + n > self.p.len() {
            self.fail(Refusal::Encoding);
            return false;
        }
        true
    }
    fn u8(&mut self) -> u8 {
        if !self.need(1) {
            return 0;
        }
        let v = self.p[self.pos];
        self.pos += 1;
        v
    }
    fn u32(&mut self) -> u32 {
        if !self.need(4) {
            return 0;
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.p[self.pos..self.pos + 4]);
        self.pos += 4;
        u32::from_le_bytes(b)
    }
    fn u64(&mut self) -> u64 {
        if !self.need(8) {
            return 0;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.p[self.pos..self.pos + 8]);
        self.pos += 8;
        u64::from_le_bytes(b)
    }
    fn f64(&mut self) -> f64 {
        f64::from_bits(self.u64())
    }
    fn dig(&mut self) -> Digest32 {
        let mut d = [0u8; DIGEST_SIZE];
        if !self.need(DIGEST_SIZE) {
            return d;
        }
        d.copy_from_slice(&self.p[self.pos..self.pos + DIGEST_SIZE]);
        self.pos += DIGEST_SIZE;
        d
    }
    /// Mirrors `r_hdr`: a short header is ENCODING, a wrong kind is KIND,
    /// a wrong version is ENCODING.
    fn hdr(&mut self, want: Kind) {
        let k = self.u8();
        let v = self.u8();
        if self.st.is_some() {
            return;
        }
        if k != want as u8 {
            self.fail(Refusal::Kind);
            return;
        }
        if v != FORMAT_VERSION {
            self.fail(Refusal::Encoding);
        }
    }
    /// Mirrors `r_end`: earlier failure first, then trailing bytes.
    fn end(&self) -> Result<(), Refusal> {
        if let Some(r) = self.st {
            return Err(r);
        }
        if self.pos != self.p.len() {
            return Err(Refusal::Encoding);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- writer

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Writer { buf: Vec::new() }
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    /// Mirrors `w_f64`: +0.0 and -0.0 both encode as all-zero bits.
    fn f64(&mut self, d: f64) {
        let bits = if d != 0.0 { d.to_bits() } else { 0 };
        self.u64(bits);
    }
    fn dig(&mut self, d: &Digest32) {
        self.buf.extend_from_slice(d);
    }
    fn hdr(&mut self, k: Kind) {
        self.u8(k as u8);
        self.u8(FORMAT_VERSION);
    }
}

fn ids_ascending<T>(entries: &[(u32, T)]) -> bool {
    entries.windows(2).all(|w| w[1].0 > w[0].0)
}

// ------------------------------------------------------------ validation

/// Raw constraint as read off the wire, before enum conversion. The check
/// runs on raw values in the exact order of `rx_dual_check_constraint`.
struct RawConstraint {
    resource_id: u32,
    unit: u32,
    cls: u32,
    budget: f64,
    budget_contract: Digest32,
    observation_ref: Digest32,
    estimate_ref: Digest32,
    estimate_kind: u32,
    estimate: f64,
    uncertainty: f64,
    calibration_ref: Digest32,
    lambda: f64,
    lambda_state: u32,
    controller_id: Digest32,
    generation: u64,
    tick: u64,
    evidence_root: Digest32,
    parent: Digest32,
}

impl RawConstraint {
    fn check(self) -> Result<ConstraintState, Refusal> {
        let unit = Unit::from_u32(self.unit).ok_or(Refusal::Unit)?;
        // INVARIANT is unconstructible; UNDECLARED is never defaulted.
        let class = Class::from_u32(self.cls).ok_or(Refusal::Class)?;
        if !(self.budget.is_finite()
            && self.estimate.is_finite()
            && self.uncertainty.is_finite()
            && self.lambda.is_finite())
        {
            return Err(Refusal::NonFinite);
        }
        if self.uncertainty < 0.0 || self.lambda < 0.0 {
            return Err(Refusal::Range);
        }
        let estimate_kind = EstimateKind::from_u32(self.estimate_kind).ok_or(Refusal::Kind)?;
        let lambda_state = LambdaState::from_u32(self.lambda_state).ok_or(Refusal::Range)?;
        if digest_is_zero(&self.budget_contract)
            || digest_is_zero(&self.estimate_ref)
            || digest_is_zero(&self.controller_id)
            || digest_is_zero(&self.evidence_root)
        {
            return Err(Refusal::Digest);
        }
        if estimate_kind == EstimateKind::Measured && digest_is_zero(&self.observation_ref) {
            return Err(Refusal::Digest);
        }
        if digest_is_zero(&self.calibration_ref) && lambda_state == LambdaState::Fresh {
            return Err(Refusal::Calibration);
        }
        if (self.tick == 0) != digest_is_zero(&self.parent) {
            return Err(Refusal::Digest);
        }
        Ok(ConstraintState {
            resource_id: self.resource_id,
            unit,
            class,
            budget: self.budget,
            budget_contract: self.budget_contract,
            observation_ref: self.observation_ref,
            estimate_ref: self.estimate_ref,
            estimate_kind,
            estimate: self.estimate,
            uncertainty: self.uncertainty,
            calibration_ref: self.calibration_ref,
            lambda: self.lambda,
            lambda_state,
            controller_id: self.controller_id,
            generation: self.generation,
            tick: self.tick,
            evidence_root: self.evidence_root,
            parent: self.parent,
        })
    }
}

fn check_resource(
    resource_id: u32,
    unit: u32,
    scale: f64,
    contract: Digest32,
) -> Result<Resource, Refusal> {
    let unit = Unit::from_u32(unit).ok_or(Refusal::Unit)?;
    if !scale.is_finite() {
        return Err(Refusal::NonFinite);
    }
    if scale <= 0.0 {
        return Err(Refusal::Scale);
    }
    if digest_is_zero(&contract) {
        return Err(Refusal::Digest);
    }
    Ok(Resource {
        resource_id,
        unit,
        scale,
        contract,
    })
}

fn check_controller(c: &Controller) -> Result<(), Refusal> {
    if !(c.eta.is_finite() && c.rho.is_finite() && c.k_sigma.is_finite()) {
        return Err(Refusal::NonFinite);
    }
    if c.eta < 0.0 || c.rho < 0.0 || c.rho > 1.0 || c.k_sigma < 0.0 {
        return Err(Refusal::Range);
    }
    if c.max_age == 0 || c.cadence == 0 {
        return Err(Refusal::Range);
    }
    if c.entries.is_empty() || c.entries.len() > MAX_RESOURCES as usize {
        return Err(Refusal::Range);
    }
    if !ids_ascending(&c.entries) {
        return Err(Refusal::Resource);
    }
    for (_, lambda_max) in &c.entries {
        if !lambda_max.is_finite() {
            return Err(Refusal::NonFinite);
        }
        if *lambda_max <= 0.0 {
            return Err(Refusal::Range);
        }
    }
    Ok(())
}

fn check_price_vector(v: &PriceVector) -> Result<(), Refusal> {
    if digest_is_zero(&v.context) {
        return Err(Refusal::Digest);
    }
    if v.entries.is_empty() || v.entries.len() > MAX_RESOURCES as usize {
        return Err(Refusal::Range);
    }
    if !ids_ascending(&v.entries) {
        return Err(Refusal::Resource);
    }
    for (_, state) in &v.entries {
        if digest_is_zero(state) {
            return Err(Refusal::Digest);
        }
    }
    Ok(())
}

// --------------------------------------------------------- decode / encode

pub fn decode_resource(buf: &[u8]) -> Result<Resource, Refusal> {
    let mut r = Reader::new(buf);
    r.hdr(Kind::Resource);
    let resource_id = r.u32();
    let unit = r.u32();
    let scale = r.f64();
    let contract = r.dig();
    r.end()?;
    check_resource(resource_id, unit, scale, contract)
}

pub fn encode_resource(x: &Resource) -> Vec<u8> {
    let mut w = Writer::new();
    w.hdr(Kind::Resource);
    w.u32(x.resource_id);
    w.u32(x.unit as u32);
    w.f64(x.scale);
    w.dig(&x.contract);
    w.buf
}

pub fn decode_constraint(buf: &[u8]) -> Result<ConstraintState, Refusal> {
    let mut r = Reader::new(buf);
    r.hdr(Kind::Constraint);
    let raw = RawConstraint {
        resource_id: r.u32(),
        unit: r.u32(),
        cls: r.u32(),
        budget: r.f64(),
        budget_contract: r.dig(),
        observation_ref: r.dig(),
        estimate_ref: r.dig(),
        estimate_kind: r.u32(),
        estimate: r.f64(),
        uncertainty: r.f64(),
        calibration_ref: r.dig(),
        lambda: r.f64(),
        lambda_state: r.u32(),
        controller_id: r.dig(),
        generation: r.u64(),
        tick: r.u64(),
        evidence_root: r.dig(),
        parent: r.dig(),
    };
    r.end()?;
    raw.check()
}

pub fn encode_constraint(s: &ConstraintState) -> Vec<u8> {
    let mut w = Writer::new();
    w.hdr(Kind::Constraint);
    w.u32(s.resource_id);
    w.u32(s.unit as u32);
    w.u32(s.class as u32);
    w.f64(s.budget);
    w.dig(&s.budget_contract);
    w.dig(&s.observation_ref);
    w.dig(&s.estimate_ref);
    w.u32(s.estimate_kind as u32);
    w.f64(s.estimate);
    w.f64(s.uncertainty);
    w.dig(&s.calibration_ref);
    w.f64(s.lambda);
    w.u32(s.lambda_state as u32);
    w.dig(&s.controller_id);
    w.u64(s.generation);
    w.u64(s.tick);
    w.dig(&s.evidence_root);
    w.dig(&s.parent);
    w.buf
}

pub fn decode_controller(buf: &[u8]) -> Result<Controller, Refusal> {
    let mut r = Reader::new(buf);
    r.hdr(Kind::Controller);
    let eta = r.f64();
    let rho = r.f64();
    let k_sigma = r.f64();
    let max_age = r.u64();
    let cadence = r.u64();
    let n = r.u32();
    if let Some(st) = r.st {
        return Err(st);
    }
    if n == 0 || n > MAX_RESOURCES {
        return Err(Refusal::Range);
    }
    let mut entries = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let id = r.u32();
        let lambda_max = r.f64();
        entries.push((id, lambda_max));
    }
    r.end()?;
    let c = Controller {
        eta,
        rho,
        k_sigma,
        max_age,
        cadence,
        entries,
    };
    check_controller(&c)?;
    Ok(c)
}

pub fn encode_controller(c: &Controller) -> Vec<u8> {
    let mut w = Writer::new();
    w.hdr(Kind::Controller);
    w.f64(c.eta);
    w.f64(c.rho);
    w.f64(c.k_sigma);
    w.u64(c.max_age);
    w.u64(c.cadence);
    w.u32(c.entries.len() as u32);
    for (id, lambda_max) in &c.entries {
        w.u32(*id);
        w.f64(*lambda_max);
    }
    w.buf
}

pub fn decode_price_vector(buf: &[u8]) -> Result<PriceVector, Refusal> {
    let mut r = Reader::new(buf);
    r.hdr(Kind::PriceVector);
    let generation = r.u64();
    let context = r.dig();
    let n = r.u32();
    if let Some(st) = r.st {
        return Err(st);
    }
    if n == 0 || n > MAX_RESOURCES {
        return Err(Refusal::Range);
    }
    let mut entries = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let id = r.u32();
        let state = r.dig();
        entries.push((id, state));
    }
    r.end()?;
    let v = PriceVector {
        generation,
        context,
        entries,
    };
    check_price_vector(&v)?;
    Ok(v)
}

pub fn encode_price_vector(v: &PriceVector) -> Vec<u8> {
    let mut w = Writer::new();
    w.hdr(Kind::PriceVector);
    w.u64(v.generation);
    w.dig(&v.context);
    w.u32(v.entries.len() as u32);
    for (id, state) in &v.entries {
        w.u32(*id);
        w.dig(state);
    }
    w.buf
}

// --------------------------------------------------------------- identity

/// Digests are taken over the canonical re-encoding of a validated record,
/// exactly as `rx_dual_digest_*` do (so a non-canonical `-0.0` on the wire
/// still yields the canonical digest).
pub fn digest_resource(x: &Resource) -> Digest32 {
    domain_digest(DOMAIN_RESOURCE, &encode_resource(x))
}

pub fn digest_constraint(s: &ConstraintState) -> Digest32 {
    domain_digest(DOMAIN_CONSTRAINT, &encode_constraint(s))
}

pub fn digest_controller(c: &Controller) -> Digest32 {
    domain_digest(DOMAIN_CONTROLLER, &encode_controller(c))
}

pub fn digest_price_vector(v: &PriceVector) -> Digest32 {
    domain_digest(DOMAIN_PRICE_VECTOR, &encode_price_vector(v))
}

/// Decode a record of the given kind from `bytes` and compare its canonical
/// digest with `expected`. Any refusal or mismatch is an `Err`.
pub fn verify_digest(kind: Kind, bytes: &[u8], expected: &Digest32) -> Result<(), VerifyError> {
    let actual = match kind {
        Kind::Resource => digest_resource(&decode_resource(bytes)?),
        Kind::Constraint => digest_constraint(&decode_constraint(bytes)?),
        Kind::Controller => digest_controller(&decode_controller(bytes)?),
        Kind::PriceVector => digest_price_vector(&decode_price_vector(bytes)?),
    };
    if &actual == expected {
        Ok(())
    } else {
        Err(VerifyError::DigestMismatch {
            expected: *expected,
            actual,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Refused(Refusal),
    DigestMismatch {
        expected: Digest32,
        actual: Digest32,
    },
}

impl From<Refusal> for VerifyError {
    fn from(r: Refusal) -> Self {
        VerifyError::Refused(r)
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Refused(r) => write!(f, "refused: {}", r),
            VerifyError::DigestMismatch { expected, actual } => write!(
                f,
                "digest mismatch: expected {} got {}",
                hex::encode(expected),
                hex::encode(actual)
            ),
        }
    }
}
