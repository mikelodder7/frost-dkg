//! Curve25519 wrappers with a scalar type that implements `PrimeFieldBits`.

use core::{
    fmt::{self, Debug, Formatter},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use curve25519_dalek::{
    edwards::SubgroupPoint as DalekSubgroupPoint, ristretto::RistrettoPoint as DalekRistrettoPoint,
    scalar::Scalar as DalekScalar,
};
use elliptic_curve::{
    ff::{Field, FieldBits, PrimeField, PrimeFieldBits},
    group::{Group, GroupEncoding, prime::PrimeGroup},
    rand_core::TryRng,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
};

/// Scalar field for Curve25519 groups with `PrimeFieldBits` support.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct Scalar(DalekScalar);

impl Scalar {
    /// Convert into the inner dalek scalar.
    pub fn into_inner(self) -> DalekScalar {
        self.0
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Scalar").field(&self.0).finish()
    }
}

impl From<DalekScalar> for Scalar {
    fn from(value: DalekScalar) -> Self {
        Self(value)
    }
}

impl From<Scalar> for DalekScalar {
    fn from(value: Scalar) -> Self {
        value.0
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Self(DalekScalar::from(value))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(DalekScalar::conditional_select(&a.0, &b.0, choice))
    }
}

macro_rules! impl_scalar_binop {
    ($trait:ident, $method:ident, $op:tt) => {
        impl $trait for Scalar {
            type Output = Self;

            fn $method(self, rhs: Self) -> Self::Output {
                Self(self.0 $op rhs.0)
            }
        }

        impl $trait<&Scalar> for Scalar {
            type Output = Self;

            fn $method(self, rhs: &Scalar) -> Self::Output {
                Self(self.0 $op rhs.0)
            }
        }
    };
}

macro_rules! impl_scalar_assignop {
    ($trait:ident, $method:ident, $op:tt) => {
        impl $trait for Scalar {
            fn $method(&mut self, rhs: Self) {
                self.0 = self.0 $op rhs.0;
            }
        }

        impl $trait<&Scalar> for Scalar {
            fn $method(&mut self, rhs: &Scalar) {
                self.0 = self.0 $op rhs.0;
            }
        }
    };
}

impl_scalar_binop!(Add, add, +);
impl_scalar_binop!(Sub, sub, -);
impl_scalar_binop!(Mul, mul, *);
impl_scalar_assignop!(AddAssign, add_assign, +);
impl_scalar_assignop!(SubAssign, sub_assign, -);
impl_scalar_assignop!(MulAssign, mul_assign, *);

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl Sum for Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, item| acc + item)
    }
}

impl<'a> Sum<&'a Self> for Scalar {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, item| acc + item)
    }
}

impl Product for Scalar {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |acc, item| acc * item)
    }
}

impl<'a> Product<&'a Self> for Scalar {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |acc, item| acc * item)
    }
}

impl Field for Scalar {
    const ZERO: Self = Self(DalekScalar::ZERO);
    const ONE: Self = Self(DalekScalar::ONE);

    fn try_random<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        DalekScalar::try_random(rng).map(Self)
    }

    fn square(&self) -> Self {
        Self(self.0.square())
    }

    fn double(&self) -> Self {
        Self(self.0.double())
    }

    fn invert(&self) -> CtOption<Self> {
        <DalekScalar as Field>::invert(&self.0).map(Self)
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        let (choice, value) = DalekScalar::sqrt_ratio(&num.0, &div.0);
        (choice, Self(value))
    }

    fn sqrt(&self) -> CtOption<Self> {
        <DalekScalar as Field>::sqrt(&self.0).map(Self)
    }
}

impl PrimeField for Scalar {
    type Repr = <DalekScalar as PrimeField>::Repr;

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        DalekScalar::from_repr(repr).map(Self)
    }

    fn from_repr_vartime(repr: Self::Repr) -> Option<Self> {
        DalekScalar::from_repr_vartime(repr).map(Self)
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_repr()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }

    const MODULUS: &'static str = <DalekScalar as PrimeField>::MODULUS;
    const NUM_BITS: u32 = <DalekScalar as PrimeField>::NUM_BITS;
    const CAPACITY: u32 = <DalekScalar as PrimeField>::CAPACITY;
    const TWO_INV: Self = Self(<DalekScalar as PrimeField>::TWO_INV);
    const MULTIPLICATIVE_GENERATOR: Self =
        Self(<DalekScalar as PrimeField>::MULTIPLICATIVE_GENERATOR);
    const S: u32 = <DalekScalar as PrimeField>::S;
    const ROOT_OF_UNITY: Self = Self(<DalekScalar as PrimeField>::ROOT_OF_UNITY);
    const ROOT_OF_UNITY_INV: Self = Self(<DalekScalar as PrimeField>::ROOT_OF_UNITY_INV);
    const DELTA: Self = Self(<DalekScalar as PrimeField>::DELTA);
}

impl PrimeFieldBits for Scalar {
    type ReprBits = [u8; 32];

    fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
        FieldBits::new(self.0.to_bytes())
    }

    fn char_le_bits() -> FieldBits<Self::ReprBits> {
        FieldBits::new([
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ])
    }
}

macro_rules! define_point_wrapper {
    ($name:ident, $inner:ty, $generator:expr) => {
        /// Prime-order Curve25519 group point.
        #[derive(Clone, Copy, Default, Eq, PartialEq)]
        pub struct $name($inner);

        impl $name {
            /// Convert into the inner dalek point.
            pub fn into_inner(self) -> $inner {
                self.0
            }
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl ConditionallySelectable for $name {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self(<$inner>::conditional_select(&a.0, &b.0, choice))
            }
        }

        impl Neg for $name {
            type Output = Self;

            fn neg(self) -> Self::Output {
                Self(-self.0)
            }
        }

        impl Add for $name {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                Self(self.0 + rhs.0)
            }
        }

        impl Add<&$name> for $name {
            type Output = Self;

            fn add(self, rhs: &$name) -> Self::Output {
                Self(self.0 + rhs.0)
            }
        }

        impl Sub for $name {
            type Output = Self;

            fn sub(self, rhs: Self) -> Self::Output {
                Self(self.0 - rhs.0)
            }
        }

        impl Sub<&$name> for $name {
            type Output = Self;

            fn sub(self, rhs: &$name) -> Self::Output {
                Self(self.0 - rhs.0)
            }
        }

        impl AddAssign for $name {
            fn add_assign(&mut self, rhs: Self) {
                self.0 += rhs.0;
            }
        }

        impl AddAssign<&$name> for $name {
            fn add_assign(&mut self, rhs: &$name) {
                self.0 += rhs.0;
            }
        }

        impl SubAssign for $name {
            fn sub_assign(&mut self, rhs: Self) {
                self.0 -= rhs.0;
            }
        }

        impl SubAssign<&$name> for $name {
            fn sub_assign(&mut self, rhs: &$name) {
                self.0 -= rhs.0;
            }
        }

        impl Mul<Scalar> for $name {
            type Output = Self;

            fn mul(self, rhs: Scalar) -> Self::Output {
                Self(self.0 * rhs.0)
            }
        }

        impl Mul<&Scalar> for $name {
            type Output = Self;

            fn mul(self, rhs: &Scalar) -> Self::Output {
                Self(self.0 * rhs.0)
            }
        }

        impl MulAssign<Scalar> for $name {
            fn mul_assign(&mut self, rhs: Scalar) {
                self.0 *= rhs.0;
            }
        }

        impl MulAssign<&Scalar> for $name {
            fn mul_assign(&mut self, rhs: &Scalar) {
                self.0 *= rhs.0;
            }
        }

        impl Sum for $name {
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::identity(), |acc, item| acc + item)
            }
        }

        impl<'a> Sum<&'a Self> for $name {
            fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::identity(), |acc, item| acc + item)
            }
        }

        impl Group for $name {
            type Scalar = Scalar;

            fn try_random<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
                <$inner as Group>::try_random(rng).map(Self)
            }

            fn identity() -> Self {
                Self(<$inner as Group>::identity())
            }

            fn generator() -> Self {
                Self($generator)
            }

            fn is_identity(&self) -> Choice {
                self.0.is_identity()
            }

            fn double(&self) -> Self {
                Self(self.0.double())
            }

            fn mul_by_generator(scalar: &Self::Scalar) -> Self {
                Self(<$inner as Group>::mul_by_generator(&scalar.0))
            }
        }

        impl GroupEncoding for $name {
            type Repr = <$inner as GroupEncoding>::Repr;

            fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
                <$inner as GroupEncoding>::from_bytes(bytes).map(Self)
            }

            fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
                <$inner as GroupEncoding>::from_bytes_unchecked(bytes).map(Self)
            }

            fn to_bytes(&self) -> Self::Repr {
                self.0.to_bytes()
            }
        }

        impl PrimeGroup for $name {}
    };
}

define_point_wrapper!(
    RistrettoPoint,
    DalekRistrettoPoint,
    curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
);
define_point_wrapper!(
    EdwardsPoint,
    DalekSubgroupPoint,
    DalekSubgroupPoint::generator()
);
