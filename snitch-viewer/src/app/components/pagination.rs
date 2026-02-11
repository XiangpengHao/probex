use dioxus::prelude::*;

#[component]
pub fn Pager(
    total_pages: usize,
    current_page: usize,
    on_prev: EventHandler<()>,
    on_next: EventHandler<()>,
) -> Element {
    if total_pages <= 1 {
        return rsx! {};
    }

    rsx! {
        div { class: "flex justify-center gap-2",
            button {
                class: "px-3 py-1.5 text-sm border border-gray-200 rounded bg-white hover:bg-gray-50 disabled:opacity-40",
                disabled: current_page == 0,
                onclick: move |_| on_prev.call(()),
                "← Prev"
            }
            button {
                class: "px-3 py-1.5 text-sm border border-gray-200 rounded bg-white hover:bg-gray-50 disabled:opacity-40",
                disabled: current_page + 1 >= total_pages,
                onclick: move |_| on_next.call(()),
                "Next →"
            }
        }
    }
}
