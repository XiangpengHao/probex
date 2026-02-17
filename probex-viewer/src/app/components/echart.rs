use charming::Chart;
use dioxus::prelude::*;

static CHART_ID_COUNTER: GlobalSignal<u64> = Signal::global(|| 0);

fn next_chart_id() -> String {
    let id = CHART_ID_COUNTER();
    *CHART_ID_COUNTER.write() = id + 1;
    format!("echart-{id}")
}

#[component]
pub fn EChart(chart: Chart, height: String) -> Element {
    let chart_id = use_hook(next_chart_id);
    let chart_json = chart.to_string();

    // Store chart JSON in a signal so use_effect can track it as a reactive
    // dependency.  peek() avoids subscribing the component itself to the
    // signal (which would cause redundant re-renders).
    let mut chart_data = use_signal(|| chart_json.clone());
    if *chart_data.peek() != chart_json {
        chart_data.set(chart_json);
    }

    let chart_id_inner = chart_id.clone();
    use_effect(move || {
        let json = chart_data(); // reads signal → reactive dependency
        let js = format!(
            r#"
            (function() {{
                var el = document.getElementById("{chart_id_inner}");
                if (!el) return;
                var instance = echarts.getInstanceByDom(el) || echarts.init(el);
                instance.setOption({json}, true);
                if (!el._ecResizeObs) {{
                    el._ecResizeObs = true;
                    new ResizeObserver(function() {{ instance.resize(); }}).observe(el);
                }}
            }})();
            "#
        );
        document::eval(&js);
    });

    rsx! {
        div {
            id: "{chart_id}",
            style: "width: 100%; height: {height};",
        }
    }
}
