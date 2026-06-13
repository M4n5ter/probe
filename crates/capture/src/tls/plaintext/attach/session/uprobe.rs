use std::collections::BTreeSet;

use aya::{
    Ebpf,
    programs::{ProbeKind, UProbe},
};

use crate::tls::{
    LibsslUprobeAttachKind, LibsslUprobeAttachTargetId,
    discovery::{verify_current_mapped_library_identity, verify_current_process_generation},
};

use super::super::{
    error::LibsslUprobeAttachError,
    recipe::{LibsslUprobeAttachPointRequest, LibsslUprobeAttachRecipeRequest},
};

pub(super) struct AttachedLibsslUprobe {
    pub(super) program_name: &'static str,
    link_id: aya::programs::uprobe::UProbeLinkId,
}

pub(super) struct AttachRecipeError {
    pub(super) error: LibsslUprobeAttachError,
    pub(super) partial_state_effect: bool,
}

impl AttachRecipeError {
    fn without_side_effect(error: LibsslUprobeAttachError) -> Self {
        Self {
            error,
            partial_state_effect: false,
        }
    }

    fn with_side_effect(error: LibsslUprobeAttachError) -> Self {
        Self {
            error,
            partial_state_effect: true,
        }
    }

    pub(super) fn into_error(self) -> LibsslUprobeAttachError {
        self.error
    }
}

pub(super) fn attach_recipe_uprobes(
    ebpf: &mut Ebpf,
    loaded_programs: &mut BTreeSet<&'static str>,
    recipe: &LibsslUprobeAttachRecipeRequest,
) -> Result<Vec<AttachedLibsslUprobe>, AttachRecipeError> {
    attach_target_is_current(recipe).map_err(AttachRecipeError::without_side_effect)?;

    let mut attached = Vec::new();
    for point in &recipe.attach_points {
        if let Err(error) =
            attach_single_uprobe(ebpf, loaded_programs, recipe, point, &mut attached)
        {
            let partial_state_effect = !attached.is_empty();
            rollback_attached_uprobes(ebpf, attached)
                .map_err(AttachRecipeError::with_side_effect)?;
            return Err(AttachRecipeError {
                error,
                partial_state_effect,
            });
        }
    }
    Ok(attached)
}

fn attach_single_uprobe(
    ebpf: &mut Ebpf,
    loaded_programs: &mut BTreeSet<&'static str>,
    recipe: &LibsslUprobeAttachRecipeRequest,
    point: &LibsslUprobeAttachPointRequest,
    attached: &mut Vec<AttachedLibsslUprobe>,
) -> Result<(), LibsslUprobeAttachError> {
    let program = uprobe_program_mut(ebpf, point.program_name)?;
    if !uprobe_kind_matches_attach_kind(program.kind(), point.kind) {
        return Err(LibsslUprobeAttachError::ProgramKind {
            name: point.program_name,
            actual: probe_kind_label(program.kind()),
            expected: point.kind,
        });
    }
    if !loaded_programs.contains(point.program_name) {
        program
            .load()
            .map_err(|source| LibsslUprobeAttachError::Program {
                name: point.program_name,
                action: "load",
                source: Box::new(source),
            })?;
        loaded_programs.insert(point.program_name);
    }
    let link_id = program
        .attach(
            Some(point.library_symbol),
            point.offset,
            &recipe.library.read_path,
            Some(recipe.pid),
        )
        .map_err(|source| LibsslUprobeAttachError::Attach {
            program_name: point.program_name,
            library_symbol: point.library_symbol,
            pid: recipe.process.pid,
            target_path: recipe.library.read_path.clone(),
            source: Box::new(source),
        })?;
    attached.push(AttachedLibsslUprobe {
        program_name: point.program_name,
        link_id,
    });
    Ok(())
}

pub(super) fn rollback_attached_uprobes(
    ebpf: &mut Ebpf,
    attached: Vec<AttachedLibsslUprobe>,
) -> Result<(), LibsslUprobeAttachError> {
    for attached in attached.into_iter().rev() {
        uprobe_program_mut(ebpf, attached.program_name)?
            .detach(attached.link_id)
            .map_err(|source| LibsslUprobeAttachError::RollbackAttach {
                program_name: attached.program_name,
                source: Box::new(source),
            })?;
    }
    Ok(())
}

pub(super) fn detach_attached_uprobes_for_target(
    ebpf: &mut Ebpf,
    target: &LibsslUprobeAttachTargetId,
    attached: Vec<AttachedLibsslUprobe>,
) -> Result<(), LibsslUprobeAttachError> {
    let mut first_error = None;
    for attached in attached.into_iter().rev() {
        let result =
            match uprobe_program_mut(ebpf, attached.program_name) {
                Ok(program) => program.detach(attached.link_id).map_err(|source| {
                    LibsslUprobeAttachError::Detach {
                        program_name: attached.program_name,
                        pid: target.process.pid,
                        target_path: target.library.read_path.clone(),
                        source: Box::new(source),
                    }
                }),
                Err(error) => Err(error),
            };
        if let Err(error) = result {
            record_first_detach_error(&mut first_error, error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(())
}

pub(super) fn record_first_detach_error(
    first_error: &mut Option<LibsslUprobeAttachError>,
    error: LibsslUprobeAttachError,
) {
    if first_error.is_none() {
        *first_error = Some(error);
    }
}

fn uprobe_program_mut<'a>(
    ebpf: &'a mut Ebpf,
    program_name: &'static str,
) -> Result<&'a mut UProbe, LibsslUprobeAttachError> {
    let program = ebpf
        .program_mut(program_name)
        .ok_or(LibsslUprobeAttachError::MissingProgram { name: program_name })?;
    program
        .try_into()
        .map_err(|source| LibsslUprobeAttachError::Program {
            name: program_name,
            action: "cast",
            source: Box::new(source),
        })
}

fn attach_target_is_current(
    recipe: &LibsslUprobeAttachRecipeRequest,
) -> Result<(), LibsslUprobeAttachError> {
    if let Err(source) = verify_current_process_generation(recipe.process, &recipe.process_verifier)
    {
        return Err(LibsslUprobeAttachError::AttachProcess {
            pid: recipe.process.pid,
            source: Box::new(source),
        });
    }
    if let Err(source) = verify_current_mapped_library_identity(&recipe.library) {
        return Err(LibsslUprobeAttachError::AttachTarget {
            pid: recipe.process.pid,
            source: Box::new(source),
        });
    }
    Ok(())
}

fn uprobe_kind_matches_attach_kind(actual: ProbeKind, expected: LibsslUprobeAttachKind) -> bool {
    matches!(
        (actual, expected),
        (ProbeKind::UProbe, LibsslUprobeAttachKind::Entry)
            | (ProbeKind::URetProbe, LibsslUprobeAttachKind::Return)
    )
}

fn probe_kind_label(kind: ProbeKind) -> &'static str {
    match kind {
        ProbeKind::KProbe => "kprobe",
        ProbeKind::KRetProbe => "kretprobe",
        ProbeKind::UProbe => "uprobe",
        ProbeKind::URetProbe => "uretprobe",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_kind_matches_aya_uprobe_kind() {
        assert!(uprobe_kind_matches_attach_kind(
            ProbeKind::UProbe,
            LibsslUprobeAttachKind::Entry
        ));
        assert!(uprobe_kind_matches_attach_kind(
            ProbeKind::URetProbe,
            LibsslUprobeAttachKind::Return
        ));
        assert!(!uprobe_kind_matches_attach_kind(
            ProbeKind::UProbe,
            LibsslUprobeAttachKind::Return
        ));
        assert!(!uprobe_kind_matches_attach_kind(
            ProbeKind::URetProbe,
            LibsslUprobeAttachKind::Entry
        ));
    }
}
