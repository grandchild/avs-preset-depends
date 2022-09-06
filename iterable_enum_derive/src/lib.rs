use proc_macro::TokenStream;
use quote::quote;
use syn;

#[proc_macro_derive(IterableEnum)]
pub fn iterable_enum_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    impl_iter(&ast)
}

fn impl_iter(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let mut variants: Vec<&syn::Ident> = Vec::new();
    match &ast.data {
        syn::Data::Enum(enum_data) => {
            for variant in &enum_data.variants {
                if !variant.fields.is_empty() {
                    panic!("Only simple enums work!");
                }
                variants.push(&variant.ident);
            }
        }
        _ => panic!("Only works for enums!"),
    };
    let gen = quote! {
        impl IterableEnum for #name {
            fn items() -> Vec<#name> {
                <Vec<#name>>::from([#(#name::#variants),*])
            }
        }
    };
    gen.into()
}
