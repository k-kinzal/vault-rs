//! Scope parser with mechanically checked base/step/exit simulation lemmas.
//! The finite-list composition is documented in docs/SCOPE_PROOF.md.
#[derive(Clone, Copy)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
struct Scan {
    mask: u8,
    length: u8,
    read: bool,
    issue: bool,
}
impl Scan {
    pub fn new() -> Self {
        Self {
            mask: 0,
            length: 0,
            read: true,
            issue: true,
        }
    }
    pub fn step(mut self, b: u8) -> Option<Self> {
        if b == b' ' {
            if self.length == 0 {
                return None;
            }
            if self.read && self.length == 11 {
                self.mask |= 1;
            }
            if self.issue && self.length == 12 {
                self.mask |= 2;
            }
            self.length = 0;
            self.read = true;
            self.issue = true;
        } else {
            if !(b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)) {
                return None;
            }
            self.read = self.read && b"secret:read".get(usize::from(self.length)) == Some(&b);
            self.issue = self.issue && b"secret:issue".get(usize::from(self.length)) == Some(&b);
            self.length = self.length.saturating_add(1).min(13);
        }
        Some(self)
    }
    pub fn finish(mut self) -> Option<u8> {
        if self.length == 0 {
            return None;
        }
        if self.read && self.length == 11 {
            self.mask |= 1;
        }
        if self.issue && self.length == 12 {
            self.mask |= 2;
        }
        Some(self.mask)
    }
}
pub(crate) fn parse(bytes: &[u8]) -> Option<u8> {
    if bytes.is_empty() || bytes.len() > 256 {
        return None;
    }
    let mut state = Scan::new();
    for &byte in bytes {
        state = state.step(byte)?;
    }
    state.finish()
}
#[cfg(kani)]
fn reference_step(state: u8, mask: u8, b: u8) -> Option<(u8, u8)> {
    if b == 32 {
        if state == 0 {
            return None;
        }
        Some((
            0,
            mask | if state == 11 {
                1
            } else if state == 16 {
                2
            } else {
                0
            },
        ))
    } else {
        if !(b == 33 || (35..=91).contains(&b) || (93..=126).contains(&b)) {
            return None;
        }
        let state = match (state, b) {
            (0, b's') => 1,
            (1, b'e') => 2,
            (2, b'c') => 3,
            (3, b'r') => 4,
            (4, b'e') => 5,
            (5, b't') => 6,
            (6, b':') => 7,
            (7, b'r') => 8,
            (8, b'e') => 9,
            (9, b'a') => 10,
            (10, b'd') => 11,
            (7, b'i') => 12,
            (12, b's') => 13,
            (13, b's') => 14,
            (14, b'u') => 15,
            (15, b'e') => 16,
            _ => 17,
        };
        Some((state, mask))
    }
}
#[cfg(kani)]
fn reference_finish(state: u8, mask: u8) -> Option<u8> {
    if state == 0 {
        None
    } else {
        Some(
            mask | if state == 11 {
                1
            } else if state == 16 {
                2
            } else {
                0
            },
        )
    }
}
#[cfg(kani)]
fn related(mask: u8, length: u8, read: bool, issue: bool, state: u8, reference_mask: u8) -> bool {
    mask <= 3
        && mask == reference_mask
        && match state {
            0..=7 => length == state && read && issue,
            8..=11 => length == state && read && !issue,
            12..=16 => length == state - 4 && !read && issue,
            17 => (1..=13).contains(&length) && !read && !issue,
            _ => false,
        }
}

#[cfg(kani)]
#[kani::proof]
fn base() {
    let s = Scan::new();
    assert!(related(s.mask, s.length, s.read, s.issue, 0, 0));
}
#[cfg(kani)]
#[kani::proof]
fn step_preserves_relation_and_error_equivalence() {
    let s: Scan = kani::any();
    let r: u8 = kani::any();
    let m: u8 = kani::any();
    let b: u8 = kani::any();
    kani::assume(related(s.mask, s.length, s.read, s.issue, r, m));
    let actual = s.step(b);
    let expected = reference_step(r, m, b);
    assert_eq!(actual.is_some(), expected.is_some());
    if let (Some(a), Some((r, m))) = (actual, expected) {
        assert!(related(a.mask, a.length, a.read, a.issue, r, m));
    }
}
#[cfg(kani)]
#[kani::proof]
fn finalization_equivalent() {
    let s: Scan = kani::any();
    let r: u8 = kani::any();
    let m: u8 = kani::any();
    kani::assume(related(s.mask, s.length, s.read, s.issue, r, m));
    assert_eq!(s.finish(), reference_finish(r, m));
}
