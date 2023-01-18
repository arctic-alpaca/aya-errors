macro_rules! generate_matching_enum_impl {
    (
        $(#[doc = $docs:literal])*
        #[repr($repr_type:ty)]
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant_name:ident = $variant_value:expr,
            )*
        }
        (error_value: $error_value:expr),
        (lookup_table: $lookup_table_indicator:expr)
    ) => {
         paste::paste! {
            $(#[doc = $docs])*
            $(#[$enum_meta])*
            #[repr($repr_type)]
            $enum_vis enum $enum_name {
                $(
                    $(#[$variant_meta])*
                    $variant_name = $variant_value,
                )*
                [<$enum_name:camel ErrorVariant>] = $error_value,
            }

            #[cfg(feature = "fmt")]
            impl core::fmt::Display for $enum_name {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "{:?}", self)
                }
            }

            $enum_vis const [<$enum_name:snake:upper _TABLE>]: [$enum_name;<$repr_type>::MAX as usize + 1]
                = $enum_name::generator();

            impl $enum_name  {
                #[cfg_attr(feature = "inline", inline(always))]
                $enum_vis fn lookup(value: $repr_type) -> core::result::Result<Self, [<$enum_name ParsingError>]> {
                    if $lookup_table_indicator {
                        let res = [<$enum_name:snake:upper _TABLE>][value as usize];
                        if res != $enum_name::[<$enum_name:camel ErrorVariant>] {
                            Ok(res)
                        } else{
                            return Err([<$enum_name ParsingError>]::[<NoRecognized $enum_name>] {
                                [<$enum_name:snake>]: value
                            });
                        }
                    } else {
                        match value {
                            $($variant_value => Ok($enum_name::$variant_name),)*
                            _ => Err([<$enum_name ParsingError>]::[<NoRecognized $enum_name>] {
                                [<$enum_name:snake>]: value
                            }),
                        }
                    }
                }

                $enum_vis const fn generator() -> [$enum_name;(<$repr_type>::MAX as usize + 1) as usize] {
                    // We use <$repr_type>::MAX + 1 as <$repr_type>::MAX is the max value and we need
                    // the amount of values that can be represented. +1 accounts for the 0.
                    let mut table = [$enum_name::[<$enum_name:camel ErrorVariant>];(<$repr_type>::MAX as usize + 1) as usize];
                    // Set all valid values, rest stays at $enum_name::$error_variant.
                    $(table[$variant_value] = $enum_name::$variant_name;)*
                    table
                }
            }

            #[cfg_attr(feature = "fmt", derive(Debug))]
            #[derive(Copy, Clone, Eq, PartialEq)]
            $enum_vis enum [<$enum_name ParsingError>] {
                [<NoRecognized $enum_name>] { [<$enum_name:snake>]: $repr_type },
            }

            #[cfg(feature = "fmt")]
            impl core::fmt::Display for [<$enum_name ParsingError>] {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    match self {
                        Self::[<NoRecognized $enum_name>]{ [<$enum_name:snake>] } => {
                            write!(f, "No valid ether type, was: {:?}", [<$enum_name:snake>])
                        }
                    }
                }
            }

            #[cfg(feature = "error_trait")]
            impl core::error::Error for [<$enum_name ParsingError>] {}
        }
    }
}
pub(crate) use generate_matching_enum_impl;
