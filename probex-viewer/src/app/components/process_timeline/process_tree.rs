use std::collections::{HashMap, HashSet};

use crate::api::ProcessLifetime;

pub(super) fn event_badge_class(enabled: bool, event_type: &str) -> String {
    if enabled {
        format!(
            "inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border {} bg-transparent hover:bg-gray-50",
            event_badge_tone(event_type)
        )
    } else {
        "inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border border-gray-200 text-gray-400 bg-transparent hover:bg-gray-50".to_string()
    }
}

fn event_badge_tone(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "border-blue-300 text-blue-700",
        "process_fork" => "border-green-300 text-green-700",
        "process_exit" => "border-red-300 text-red-700",
        "page_fault" => "border-amber-300 text-amber-700",
        _ if event_type.contains("read") => "border-sky-300 text-sky-700",
        _ if event_type.contains("write") => "border-orange-300 text-orange-700",
        _ if event_type.contains("mmap")
            || event_type.contains("munmap")
            || event_type.contains("brk") =>
        {
            "border-purple-300 text-purple-700"
        }
        _ if event_type.contains("syscall") => "border-indigo-300 text-indigo-700",
        _ => "border-gray-300 text-gray-700",
    }
}

/// Tree position info for rendering tree lines
#[derive(Clone, PartialEq)]
pub(super) struct TreePosition {
    /// For each ancestor level, whether that ancestor was the last child at its level
    /// This determines whether to draw | (not last) or space (last) for each column
    pub ancestor_is_last: Vec<bool>,
    /// Whether this node is the last child of its parent
    pub is_last_child: bool,
    /// Whether this node has children
    pub has_children: bool,
    /// Number of total descendants (for collapse badge)
    pub descendant_count: usize,
}

#[derive(PartialEq)]
pub(super) struct ProcessTreeModel {
    pub sorted_processes: Vec<ProcessLifetime>,
    pub visible_process_rows: Vec<(ProcessLifetime, TreePosition)>,
    pub collapsible_nodes: Vec<u32>,
}

pub(super) fn build_process_tree(
    processes: &[ProcessLifetime],
    collapsed_nodes: &HashSet<u32>,
) -> ProcessTreeModel {
    let mut sorted_processes = processes.to_vec();
    sorted_processes.sort_by_key(|p| p.start_ns);

    let process_by_pid: HashMap<u32, &ProcessLifetime> =
        sorted_processes.iter().map(|p| (p.pid, p)).collect();

    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut root_pids: Vec<u32> = Vec::new();

    for proc in &sorted_processes {
        if let Some(parent_pid) = proc.parent_pid {
            if process_by_pid.contains_key(&parent_pid) {
                children_map.entry(parent_pid).or_default().push(proc.pid);
            } else {
                root_pids.push(proc.pid);
            }
        } else {
            root_pids.push(proc.pid);
        }
    }

    for children in children_map.values_mut() {
        children.sort_by_key(|pid| process_by_pid.get(pid).map(|p| p.start_ns).unwrap_or(0));
    }
    root_pids.sort_by_key(|pid| process_by_pid.get(pid).map(|p| p.start_ns).unwrap_or(0));

    let mut ordered_pid_rows: Vec<(u32, TreePosition)> = Vec::with_capacity(sorted_processes.len());
    let root_count = root_pids.len();
    for (idx, root_pid) in root_pids.iter().enumerate() {
        let is_last_root = idx == root_count - 1;
        append_visible_rows(
            *root_pid,
            &children_map,
            collapsed_nodes,
            Vec::new(),
            is_last_root,
            &mut ordered_pid_rows,
        );
    }

    let visible_process_rows = ordered_pid_rows
        .iter()
        .filter_map(|(pid, tree_pos)| {
            process_by_pid
                .get(pid)
                .map(|proc| ((*proc).clone(), tree_pos.clone()))
        })
        .collect::<Vec<_>>();

    let collapsible_nodes = children_map
        .iter()
        .filter_map(|(pid, children)| (!children.is_empty()).then_some(*pid))
        .collect();

    ProcessTreeModel {
        sorted_processes,
        visible_process_rows,
        collapsible_nodes,
    }
}

fn count_descendants(pid: u32, children_map: &HashMap<u32, Vec<u32>>) -> usize {
    let mut count = 0;
    if let Some(children) = children_map.get(&pid) {
        count += children.len();
        for child in children {
            count += count_descendants(*child, children_map);
        }
    }
    count
}

fn append_visible_rows(
    pid: u32,
    children_map: &HashMap<u32, Vec<u32>>,
    collapsed_nodes: &HashSet<u32>,
    ancestor_is_last: Vec<bool>,
    is_last_child: bool,
    out: &mut Vec<(u32, TreePosition)>,
) {
    let has_children = children_map
        .get(&pid)
        .map(|c| !c.is_empty())
        .unwrap_or(false);
    let descendant_count = if collapsed_nodes.contains(&pid) {
        count_descendants(pid, children_map)
    } else {
        0
    };

    out.push((
        pid,
        TreePosition {
            ancestor_is_last: ancestor_is_last.clone(),
            is_last_child,
            has_children,
            descendant_count,
        },
    ));

    if collapsed_nodes.contains(&pid) {
        return;
    }
    if let Some(children) = children_map.get(&pid) {
        let child_count = children.len();
        for (i, child) in children.iter().enumerate() {
            let is_last = i == child_count - 1;
            let mut child_ancestor_is_last = ancestor_is_last.clone();
            child_ancestor_is_last.push(is_last_child);
            append_visible_rows(
                *child,
                children_map,
                collapsed_nodes,
                child_ancestor_is_last,
                is_last,
                out,
            );
        }
    }
}
