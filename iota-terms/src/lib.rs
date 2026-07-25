pub mod consent;
pub mod terms_getter;

pub use terms_getter::Type as TermsType;
pub use terms_getter::get_current_docs;
pub use terms_getter::get_link;
pub use terms_getter::get_newest_docs;
pub use terms_getter::get_newest_link;
pub use terms_getter::get_terms;

pub mod doc;

pub use doc::Doc;
