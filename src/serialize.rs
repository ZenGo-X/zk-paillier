pub mod bigint {

    use curv::BigInt;
    use serde::{de, ser};
    use std::fmt;

    pub fn serialize<S: ser::Serializer>(x: &BigInt, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&x.to_str_radix(10))
    }

    pub fn deserialize<'de, D: de::Deserializer<'de>>(deserializer: D) -> Result<BigInt, D::Error> {
        struct BigIntVisitor;

        impl<'de> de::Visitor<'de> for BigIntVisitor {
            type Value = BigInt;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("bigint")
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<BigInt, E> {
                let v: BigInt = str::parse(s).map_err(de::Error::custom)?;
                Ok(v)
            }
        }

        deserializer.deserialize_str(BigIntVisitor)
    }
}

pub mod vecbigint {

    use curv::BigInt;
    use serde::de::SeqAccess;
    use serde::ser::SerializeSeq;
    use serde::{de, ser};
    use std::fmt;

    pub fn serialize<S: ser::Serializer>(
        x: &Vec<BigInt>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(x.len()))?;
        for e in x {
            seq.serialize_element(&e.to_str_radix(10))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: de::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<BigInt>, D::Error> {
        struct VecBigIntVisitor;

        impl<'de> de::Visitor<'de> for VecBigIntVisitor {
            type Value = Vec<BigInt>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("vector of bigint")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<BigInt>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values: Vec<BigInt> = Vec::new();
                while let Some(value) = seq.next_element::<String>()? {
                    values.push(BigInt::from_str_radix(&value, 10).unwrap());
                }

                Ok(values)
            }
        }

        deserializer.deserialize_seq(VecBigIntVisitor)
    }
}
