#[macro_export]
macro_rules! with_settings {
    ($body:expr) => {
        $crate::SETTINGS.with_borrow(|s| {
            let settings = s
                .as_ref()
                .unwrap_or_else(|| ic_cdk::trap("Settings are not initialized."));
            #[allow(clippy::redundant_closure_call)]
            $body(settings)
        })
    };
}