/// Support macros used to generate Oximeter metrics

/// Trait attempting to convert an arbitrary stat into the i64 format expected
/// by Oximeter.
pub trait StatXlate<T> {
    fn stat_xlate(self) -> T;
}

impl StatXlate<i64> for i64 {
    fn stat_xlate(self) -> i64 {
        self
    }
}

impl StatXlate<i64> for usize {
    fn stat_xlate(self) -> i64 {
        self as i64
    }
}

/// The counters we get from Tofino are unsigned 64-bit values, but oximeter
/// only accepts signed 64-bit values.  In practice, none of these counters
/// should ever exceed 63 bits, so this shouldn't cause any trouble.  If we
/// ever do hit an overflow, we set the value to i64::MAX as an error
/// sentinel.  The alternatives are to stop reporting any stats for the
/// given port or update all the other stats, silently leaving this one stuck
/// at its last good value.
pub const STAT_OVERFLOW: i64 = std::i64::MAX;

impl StatXlate<i64> for u64 {
    fn stat_xlate(self) -> i64 {
        use std::convert::TryInto;
        match self.try_into() {
            Ok(v) => v,
            Err(_) => STAT_OVERFLOW,
        }
    }
}

impl StatXlate<i64> for u32 {
    fn stat_xlate(self) -> i64 {
        self as i64
    }
}

/// Defines the structure representing a single boolean oximeter metric, along
/// with definitions for new() and set().
#[macro_export]
macro_rules! make_bool {
    ($name:ident, $key:ident) => {
        #[derive(Clone, Copy, Debug, Default, Metric)]
        struct $name {
            #[datum]
            $key: bool,
        }

        impl $name {
            pub fn new(val: bool) -> Self {
                $name { $key: val }
            }
        }

        impl $name {
            pub fn set(&mut self, val: bool) {
                self.$key = val;
            }
        }
    };
}

/// Defines the structure representing a single accumulating oximeter metric,
/// along with definitions for new() and set().
#[macro_export]
macro_rules! make_cumulative {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Default, Metric)]
        struct $name {
            #[datum]
            value: oximeter::types::Cumulative<i64>,
        }

        impl $name {
            pub fn new(val: impl StatXlate<i64>) -> Self {
                $name {
                    value: oximeter::types::Cumulative::new(val.stat_xlate()),
                }
            }

            pub fn set(&mut self, val: impl StatXlate<i64>) {
                self.value.set(val.stat_xlate());
            }
        }
    };
}

/// Defines the structure representing a single integral gauge oximeter metric.
#[macro_export]
macro_rules! make_gauge {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Default, Metric)]
        struct $name {
            #[datum]
            value: i64,
        }

        impl $name {
            pub fn new(val: impl StatXlate<i64>) -> Self {
                $name {
                    value: val.stat_xlate().into(),
                }
            }

            pub fn set(&mut self, val: impl StatXlate<i64>) {
                self.value = val.stat_xlate();
            }
        }
    };
}
