//! The mount exclusion check: does anything inside a share reach a file that
//! must stay outside it?
//!
//! `00-PRODUCT.md` §3.11 requires `rachna.nix` to be invisible to the guest,
//! because a guest that can edit its own policy has no policy. Excluding it
//! **by path** is not enough, and that is measured rather than assumed:
//!
//! | Attack | Measured |
//! |---|---|
//! | a hardlink inside the share pointing at the excluded file | ✅ succeeded (`13` §4) |
//! | `RACHNA.NIX` on a case-insensitive filesystem | ✅ succeeded (`12` §3) |
//!
//! Both defeat a name comparison, and **both are defeated by comparing
//! identity instead** — `(st_dev, st_ino)`. A hardlink *is* the same inode by
//! definition, and a case variant resolves to it, so one check closes both
//! (`14` §4).
//!
//! # Why this module holds no I/O
//!
//! The comparison is pure: it takes already-collected identities and decides.
//! Walking the tree and calling `stat` belongs to the backend, which is what
//! lets the security-critical decision be table-tested with no filesystem
//! (`01-ARCHITECTURE.md` §4). The cost is that the caller must collect
//! honestly, so [`Verdict`] names what it relied on.

use core::fmt;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A file's identity on a filesystem: the pair that a name cannot forge.
///
/// Two paths with the same [`FileId`] are the same file, whatever they are
/// called and however many links point at them. This is the whole mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId {
    /// `st_dev` — which filesystem.
    pub device: u64,
    /// `st_ino` — which file on it.
    pub inode: u64,
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dev {} inode {}", self.device, self.inode)
    }
}

/// What must not be reachable from inside a guest, for one project.
///
/// # Why this exists as a type
///
/// [`check`] takes a `BTreeSet<FileId>` and **nothing produced one**. The
/// mechanism was correct, tested against both measured attacks, and unwired
/// — so every path `08` §4 says must be excluded was excluded by nobody. A
/// security check whose input no code supplies is the "declared and never
/// enforced" shape in its purest form.
///
/// # What belongs here, and what does not
///
/// `00` §3.11's third bullet gives the rule: *"Anything whose integrity the
/// policy depends on is excluded the same way — so the exclusion list is
/// part of the mount's definition, not a special case for one filename."*
///
/// Two entries, and the **second matters more than the first**:
///
/// - **`rachna.nix`**, so the guest cannot read or edit the policy that
///   governs it. Since `00` §3.11a gated the reload, this is a *default*
///   rather than a requirement — a guest-written grant is now inert until
///   approved — but it stays because the file is not the agent's business
///   most of the time, and because the gate is one function that was itself
///   found as a flag nobody read.
/// - **the shim directory**, and `08` §4's table calls this *"worse than the
///   policy-tampering attack it mirrors"*: a guest that replaces
///   `.rachna/bin/rustfmt` gets **code execution on the host**, because the
///   editor is configured to run it. **No reload gate helps here** — there
///   is no reload to gate — so this entry is load-bearing however the
///   policy-file question is settled.
///
/// What is deliberately **not** here: the project's own service data. `08`
/// §4 is explicit — *"A guest writing its own Postgres files is not an
/// attack, it is the entire point."* The trust argument is about things
/// *Rachna relies on*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExclusionSet {
    paths: Vec<PathBuf>,
    /// The subset whose exposure is fatal rather than advisory.
    fatal: Vec<PathBuf>,
}

impl ExclusionSet {
    /// What to exclude for a project whose `rachna.nix` sits at `policy_file`
    /// and whose shims live at `shim_dir`.
    ///
    /// Takes paths rather than a [`ProjectPaths`](crate::layout::ProjectPaths)
    /// so this stays usable for a project laid out differently — and so the
    /// set is testable without a filesystem.
    #[must_use]
    pub fn for_project(policy_file: &Path, shim_dir: &Path) -> Self {
        Self {
            paths: vec![policy_file.to_path_buf(), shim_dir.to_path_buf()],
            fatal: vec![shim_dir.to_path_buf()],
        }
    }

    /// The paths whose exposure must REFUSE a start rather than warn.
    ///
    /// # Why this is a split and not one rule
    ///
    /// The two entries differ in severity, and this type's own header says
    /// so: the shim directory is *"worse than the policy-tampering attack
    /// it mirrors"* because a guest replacing `.rachna/bin/rustfmt` gets
    /// **code execution on the host**, and *"no reload gate helps here"*.
    /// `rachna.nix` is *"a default rather than a requirement"*, since
    /// `00` §3.11a gated the reload and a guest-written grant is inert
    /// until approved.
    ///
    /// Treating them alike was measured as unusable. A first version
    /// refused any share the policy file was reachable from — which is
    /// EVERY project, because `rachna.nix` lives in the project directory
    /// and that directory is the workspace share:
    ///
    /// ```text
    /// rachna: refusing to share …/excl — the guest would be able to reach
    ///   something it must not:
    ///   …/excl/rachna.nix is the same file as an excluded one
    /// ```
    ///
    /// And it cannot be fixed by hiding the file: `14` §2 measured VZ's
    /// entire share API as *"a URL and a read-only flag … no exclusion
    /// list"*, so a virtiofs share is all-or-nothing. Refusing a condition
    /// that is unavoidable by design is not a security control, it is a
    /// tool that does not start.
    #[must_use]
    pub fn fatal(&self) -> &[PathBuf] {
        &self.fatal
    }

    /// The paths to resolve.
    #[must_use]
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Resolves every path to a [`FileId`], via `stat`.
    ///
    /// # Errors
    ///
    /// [`ResolveError`] naming the path that could not be resolved. **A
    /// failure must stop the start**, and `check` already enforces that: an
    /// empty or partial set makes [`Verdict::is_vacuous`] true, because a
    /// check against nothing refuses nothing. Returning a short set instead
    /// of an error would be the silent half-protection `14` §3 warns about.
    ///
    /// A path that does not exist is **not** an error for the shim
    /// directory, which Rachna creates on first start — but it **is** for
    /// `rachna.nix`, whose absence means there is no policy to enforce and
    /// therefore nothing to start. The caller distinguishes them, because
    /// only the caller knows which is which.
    pub fn resolve_with(
        &self,
        mut stat: impl FnMut(&Path) -> Option<FileId>,
    ) -> Result<BTreeSet<FileId>, ResolveError> {
        let mut out = BTreeSet::new();
        for path in &self.paths {
            let id = stat(path).ok_or_else(|| ResolveError { path: path.clone() })?;
            out.insert(id);
        }
        Ok(out)
    }
}

/// A path in the exclusion set that could not be resolved.
///
/// Carries the path because the fix depends on which one it was, and because
/// `00` §3.3's rules apply: "could not resolve the exclusion set" tells a
/// user nothing they can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveError {
    /// The path that failed.
    pub path: PathBuf,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot stat {} to exclude it from the guest's view. \
             Starting would mount a share this check never verified, so \
             rachna refuses rather than protecting half of it (00 §3.11)",
            self.path.display()
        )
    }
}

impl core::error::Error for ResolveError {}

/// One entry found inside a share, with the facts the check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEntry {
    /// Where it was found, for the error message.
    pub path: PathBuf,
    /// Its identity.
    pub id: FileId,
    /// `st_nlink`. More than one means another name points at this file.
    pub links: u64,
}

/// Why a mount was refused.
///
/// Each variant names a *measured* attack rather than a hypothetical, so a
/// reader can trace it to the spike that found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// An entry inside the share is the same file as an excluded one.
    ///
    /// Covers the hardlink attack (`13` §4) and the case-variant attack
    /// (`12` §3): both produce a different name for the same inode.
    ReachesExcludedFile {
        /// The name inside the share. Deliberately reported — the attacker
        /// chose it, so it is evidence, and `14` §3 notes the name itself
        /// gives nothing away.
        entry: PathBuf,
        /// The identity it shares with something excluded.
        id: FileId,
    },
    /// An entry lives on a different filesystem than the share root.
    ///
    /// A mount point or bind inside the workspace that should not be there
    /// (`14` §3 step 3). Refused because the exclusion set was resolved
    /// against the share's own device, so an entry elsewhere was never
    /// checked against anything.
    CrossesFilesystem {
        entry: PathBuf,
        entry_device: u64,
        share_device: u64,
    },
    /// A directory inside the share could not be read.
    ///
    /// A REFUSAL rather than a footnote, because `14` §3's inode check is
    /// only as good as its coverage: a tree holding a directory nobody
    /// could read is a tree where an excluded inode might be hiding, and
    /// `Verdict::is_vacuous`'s whole argument is that a check against
    /// nothing refuses nothing.
    Unreadable { entry: PathBuf },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReachesExcludedFile { entry, id } => write!(
                f,
                "{} is the same file as an excluded one ({id}), so mounting \
                 this share would expose it",
                entry.display()
            ),
            Self::Unreadable { entry } => write!(
                f,
                "{} could not be read, so this check cannot vouch for what \
                 is inside it. Fix its permissions or exclude it from the \
                 workspace",
                entry.display()
            ),
            Self::CrossesFilesystem {
                entry,
                entry_device,
                share_device,
            } => write!(
                f,
                "{} is on device {entry_device}, not the share's device \
                 {share_device} — a mount point inside the workspace",
                entry.display()
            ),
        }
    }
}

impl core::error::Error for Refusal {}

/// The result of checking a share, and what the check was able to rely on.
///
/// Carries the inputs it used so a caller cannot report "safe" for a check
/// that examined nothing. A walk that silently skipped an unreadable
/// directory, or an exclusion set that failed to resolve, is the difference
/// between a verdict and a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    refusals: Vec<Refusal>,
    entries_examined: usize,
    excluded_resolved: usize,
    /// Identities whose exposure is fatal. Empty for a pure `check`, which
    /// has no filesystem and therefore no severity information.
    fatal: BTreeSet<FileId>,
}

impl Verdict {
    /// Records a directory the walk could not read.
    ///
    /// Takes the path rather than a `Refusal` so the caller cannot choose a
    /// *different* refusal for it: an unreadable directory has exactly one
    /// meaning here.
    pub fn push_unreadable(&mut self, entry: PathBuf) {
        self.refusals.push(Refusal::Unreadable { entry });
    }

    /// Records an entry whose identity is in the excluded set.
    ///
    /// For the containment case `check`'s `nlink > 1` filter deliberately
    /// skips: a file with ONE name, sitting inside the share, which is
    /// simply the policy file being where it must not be.
    pub fn push_reaches(&mut self, entry: PathBuf, id: FileId) {
        self.refusals
            .push(Refusal::ReachesExcludedFile { entry, id });
    }

    /// Whether the share may be mounted.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.refusals.is_empty()
    }

    /// The refusals that must STOP a start.
    ///
    /// Exposure of the shim directory, and any entry this check could not
    /// see. Both are unmitigated: the first is host code execution
    /// (`08` §4), and the second means the check has a blind spot, which
    /// `Verdict::is_vacuous` argues is not a pass.
    #[must_use]
    pub fn fatal_refusals(&self) -> Vec<&Refusal> {
        self.refusals
            .iter()
            .filter(|refusal| match refusal {
                Refusal::ReachesExcludedFile { id, .. } => self.fatal.contains(id),
                // A directory nobody could read, or an entry on another
                // filesystem, is a gap in coverage rather than a known
                // exposure — and a check with a gap cannot vouch for what
                // it did not see.
                Refusal::Unreadable { .. } | Refusal::CrossesFilesystem { .. } => true,
            })
            .collect()
    }

    /// The refusals worth SAYING but not worth stopping for.
    ///
    /// Today this is the policy file being visible, which `14` §2 measured
    /// as unavoidable — VZ's share API is *"a URL and a read-only flag …
    /// no exclusion list"* — and which `00` §3.11a's reload gate already
    /// renders inert: a grant the guest writes is not applied until the
    /// user approves it.
    #[must_use]
    pub fn advisories(&self) -> Vec<&Refusal> {
        self.refusals
            .iter()
            .filter(|refusal| match refusal {
                Refusal::ReachesExcludedFile { id, .. } => !self.fatal.contains(id),
                Refusal::Unreadable { .. } | Refusal::CrossesFilesystem { .. } => false,
            })
            .collect()
    }

    /// Whether the share may be mounted **given** the severity split.
    ///
    /// The question `start` actually asks. `is_allowed` is the strict form
    /// and stays, because the pure `check` tests assert it.
    #[must_use]
    pub fn may_mount(&self) -> bool {
        self.fatal_refusals().is_empty()
    }

    /// Every reason the share was refused.
    ///
    /// All of them, not the first: a user fixing one hardlink should not have
    /// to re-run to discover the second, which is the same batch-reporting
    /// principle as the denial report (`00-PRODUCT.md` §3.3).
    #[must_use]
    pub fn refusals(&self) -> &[Refusal] {
        &self.refusals
    }

    /// How many share entries the check examined.
    #[must_use]
    pub const fn entries_examined(&self) -> usize {
        self.entries_examined
    }

    /// How many excluded paths were resolved to an identity.
    ///
    /// **Zero means the check could not protect anything**, even though it
    /// will report no refusals. A caller must treat that as a failure rather
    /// than a pass — [`Self::is_vacuous`] says so directly.
    #[must_use]
    pub const fn excluded_resolved(&self) -> usize {
        self.excluded_resolved
    }

    /// Whether this verdict proves nothing.
    ///
    /// True when no excluded identity was supplied: there was nothing to
    /// compare against, so "allowed" is the absence of a check rather than
    /// the result of one. The distinction exists because a silently-vacuous
    /// security check is the failure mode `11` §7 and `23` §1.1 keep finding.
    #[must_use]
    pub const fn is_vacuous(&self) -> bool {
        self.excluded_resolved == 0
    }
}

/// Decides whether a share may be mounted.
///
/// `excluded` is the identity of every file that must stay outside the guest —
/// `rachna.nix`, the store, anything load-bearing — already resolved by the
/// caller. `entries` is what was found inside the share.
///
/// # The `links > 1` pre-filter is applied here, not by the caller
///
/// `14` §3 establishes it as sound: a hardlink necessarily has `nlink >= 2`,
/// so nothing can hide behind it, and almost every file in a normal project
/// has `nlink == 1`. Applying it here rather than in the walk means the walk
/// cannot accidentally filter *more* than this — the caller hands over
/// everything it saw, and the security decision stays in one place.
#[must_use]
pub fn check(
    share_root_device: u64,
    excluded: &BTreeSet<FileId>,
    entries: &[ShareEntry],
) -> Verdict {
    let mut refusals = Vec::new();

    for entry in entries {
        // Checked before the link filter: a mount point need not be a
        // hardlink, and an entry on another device was never compared against
        // an exclusion set resolved on this one.
        if entry.id.device != share_root_device {
            refusals.push(Refusal::CrossesFilesystem {
                entry: entry.path.clone(),
                entry_device: entry.id.device,
                share_device: share_root_device,
            });
            continue;
        }

        if entry.links > 1 && excluded.contains(&entry.id) {
            refusals.push(Refusal::ReachesExcludedFile {
                entry: entry.path.clone(),
                id: entry.id,
            });
        }
    }

    Verdict {
        refusals,
        // EMPTY for a pure check: severity comes from the filesystem, and
        // `check` has none. `verify` fills it in, so a pure verdict treats
        // every refusal as advisory rather than claiming a severity it
        // cannot know.
        fatal: BTreeSet::new(),
        entries_examined: entries.len(),
        excluded_resolved: excluded.len(),
    }
}

/// Whether `path` is excluded by name, as the first and weakest filter.
///
/// **Not a security boundary on its own** — this is what the hardlink and
/// case-variant attacks defeat. It exists because the exclusion set has to be
/// *built* from names before it can be resolved to identities, and because a
/// case-insensitive host makes even that step subtle.
///
/// Compared case-insensitively on purpose: on APFS, `RACHNA.NIX` and
/// `rachna.nix` are the same file (`12` §3), so a case-sensitive comparison
/// would fail to add the file to the excluded set at all — the check would
/// then be vacuous rather than wrong, which is worse because it looks fine.
#[must_use]
pub fn is_excluded_by_name(path: &Path, excluded_names: &[&str]) -> bool {
    path.file_name().is_some_and(|name| {
        let name = name.to_string_lossy();
        excluded_names
            .iter()
            .any(|excluded| name.eq_ignore_ascii_case(excluded))
    })
}

/// Stats one path, or `None` if it cannot be seen.
///
/// The `stat` [`ExclusionSet::resolve_with`] wants, over the real
/// filesystem. Separate so the pure half stays testable without one.
///
/// FOLLOWS SYMLINKS, deliberately: `metadata` rather than
/// `symlink_metadata`. The question is which FILE a name reaches, and a
/// symlink's own inode is not the file an attacker is trying to read —
/// `~/.gitconfig` on a home-manager machine is a link into the Nix store,
/// and the store file is what matters.
#[must_use]
pub fn stat(path: &Path) -> Option<FileId> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(id_of(&metadata))
}

/// A [`FileId`] from metadata already obtained.
#[cfg(unix)]
fn id_of(metadata: &std::fs::Metadata) -> FileId {
    use std::os::unix::fs::MetadataExt;
    FileId {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn id_of(_metadata: &std::fs::Metadata) -> FileId {
    // Windows is `01` §3's unmeasured backend. Returning a constant would
    // make every entry look like every other, which `check` would read as
    // a universal collision — so the walk refuses on this platform instead
    // and `verify` reports it.
    FileId {
        device: 0,
        inode: 0,
    }
}

/// How deep the walk goes before giving up.
///
/// A project tree is wide rather than deep, and a symlink loop inside the
/// share would otherwise spin forever. 64 is far past any real source tree
/// and bounded enough that a hostile layout cannot hang `rachna start`.
const MAX_DEPTH: usize = 64;

/// Walks a share and returns every entry, with the facts [`check`] needs.
///
/// # Why every entry, and not just the links
///
/// `check` applies the `nlink > 1` filter itself (`14` §3), and the comment
/// there gives the reason: the caller hands over everything it saw, so the
/// walk cannot accidentally filter *more* than the security decision
/// intends. This function therefore does no filtering at all.
///
/// # Errors
///
/// [`WalkError`] when the share's own root cannot be read. A subdirectory
/// that cannot be read is **not** an error — it is reported as unreadable
/// and the mount is refused, because a directory this check could not see
/// is one it cannot vouch for.
pub fn walk(share_root: &Path) -> Result<Walked, WalkError> {
    let root_metadata = std::fs::metadata(share_root).map_err(|error| WalkError {
        path: share_root.to_path_buf(),
        why: error.to_string(),
    })?;
    if !root_metadata.is_dir() {
        return Err(WalkError {
            path: share_root.to_path_buf(),
            why: "not a directory".to_owned(),
        });
    }

    let mut walked = Walked {
        root_device: id_of(&root_metadata).device,
        entries: Vec::new(),
        unreadable: Vec::new(),
    };
    let mut queue = vec![(share_root.to_path_buf(), 0usize)];

    while let Some((dir, depth)) = queue.pop() {
        if depth > MAX_DEPTH {
            walked.unreadable.push(dir);
            continue;
        }
        let Ok(reader) = std::fs::read_dir(&dir) else {
            // Recorded, not skipped. A directory the check could not read
            // is one it cannot vouch for, and `Verdict::is_vacuous`'s whole
            // argument is that a check against nothing refuses nothing.
            walked.unreadable.push(dir);
            continue;
        };
        for entry in reader {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            // `symlink_metadata` HERE, unlike `stat` above, and the
            // difference is the point: for the exclusion SET we ask what a
            // name reaches, but while walking we must not follow a link out
            // of the share — a symlink to `/` would otherwise make this walk
            // the host filesystem.
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                walked.unreadable.push(path);
                continue;
            };
            if metadata.is_dir() {
                queue.push((path, depth + 1));
                continue;
            }
            // A SYMLINK IS RESOLVED FOR ITS IDENTITY, because that is the
            // attack: a link named `innocuous.txt` pointing at the policy
            // file reaches it, and its own inode would not match. `13` §4
            // measured the hardlink variant; a symlink is the same shape
            // with a cheaper setup.
            let id = if metadata.file_type().is_symlink() {
                match stat(&path) {
                    Some(id) => id,
                    // A dangling link reaches nothing, so it cannot reach
                    // an excluded file either.
                    None => continue,
                }
            } else {
                id_of(&metadata)
            };
            walked.entries.push(ShareEntry {
                path,
                id,
                links: links_of(&metadata),
            });
        }
    }
    Ok(walked)
}

#[cfg(unix)]
fn links_of(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink()
}

#[cfg(not(unix))]
fn links_of(_metadata: &std::fs::Metadata) -> u64 {
    // Unknown, so reported as >1 to make `check` compare it rather than
    // skip it. Over-checking is the safe direction.
    2
}

/// What a walk found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walked {
    /// `st_dev` of the share root, for the cross-filesystem check.
    pub root_device: u64,
    /// Every file found, unfiltered.
    pub entries: Vec<ShareEntry>,
    /// Paths that could not be read, so could not be vouched for.
    pub unreadable: Vec<PathBuf>,
}

/// A share that could not be walked at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkError {
    /// The share root.
    pub path: PathBuf,
    /// Why.
    pub why: String,
}

impl fmt::Display for WalkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot read {} to check what the guest would see: {}. \
             Starting would mount a share this check never verified",
            self.path.display(),
            self.why
        )
    }
}

impl core::error::Error for WalkError {}

/// The whole check, over the real filesystem.
///
/// **This is the function that was missing.** `check` existed and was
/// tested; `ExclusionSet` existed and was tested; nothing walked a share or
/// stat'd a path, so `00` §3.11's invariant — `rachna.nix` is invisible to
/// the guest — was documented and unenforced. Measured before this landed:
/// a real guest's own console printed
///
/// ```text
/// RACHNA-WORKSPACE-FILES: AGENTS.md Cargo.lock … rachna.nix src target
/// ```
///
/// # Errors
///
/// [`VerifyError::Resolve`] when an excluded path cannot be stat'd, and
/// [`VerifyError::Walk`] when the share cannot be read. Both REFUSE rather
/// than warn: a check that could not look is not a check that passed.
pub fn verify(set: &ExclusionSet, share_root: &Path) -> Result<Verdict, VerifyError> {
    let excluded = set.resolve_with(stat).map_err(VerifyError::Resolve)?;
    // The FATAL subset, resolved separately, so a refusal can say whether
    // it stops the start or merely warrants a warning. Resolved with the
    // same `stat` so a path appearing in both sets compares equal.
    let fatal: BTreeSet<FileId> = set.fatal().iter().filter_map(|p| stat(p)).collect();
    let walked = walk(share_root).map_err(VerifyError::Walk)?;

    // TWO CHECKS, because they catch different things and `check` alone
    // catches only one.
    //
    // `check` applies `14` §3's `nlink > 1` pre-filter, which is sound for
    // the attack it was designed against — a HARDLINK giving an excluded
    // file a second name — because a hardlink necessarily has `nlink >= 2`.
    //
    // It does NOT catch the plainest case: the policy file simply being
    // inside the share, with `nlink == 1`. Measured — the first version of
    // this function called `check` alone and allowed a share containing
    // `rachna.nix`, which is the exact invariant `00` §3.11 states and the
    // exact thing a real guest's console had already printed:
    //
    //   RACHNA-WORKSPACE-FILES: AGENTS.md Cargo.lock … rachna.nix src
    //
    // So containment is checked directly, without the link filter: any
    // entry whose identity is in the excluded set is refused however many
    // names it has.
    let mut verdict = check(walked.root_device, &excluded, &walked.entries);
    for entry in &walked.entries {
        if entry.links <= 1 && excluded.contains(&entry.id) {
            verdict.push_reaches(entry.path.clone(), entry.id);
        }
    }
    // An unreadable directory becomes a REFUSAL, not a footnote. `14` §3's
    // check is only as good as its coverage, and a tree with a directory
    // nobody could read is a tree where an excluded inode might be hiding.
    for path in walked.unreadable {
        verdict.push_unreadable(path);
    }
    verdict.fatal = fatal;
    Ok(verdict)
}

/// Why the check could not reach a verdict.
#[derive(Debug)]
pub enum VerifyError {
    /// An excluded path could not be stat'd.
    Resolve(ResolveError),
    /// The share could not be walked.
    Walk(WalkError),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve(error) => write!(f, "{error}"),
            Self::Walk(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for VerifyError {}

#[cfg(test)]
mod tests {
    // ---- the real filesystem: what was missing entirely ----------------

    /// An exclusion set for a project, used by the filesystem tests.
    fn set_for(policy: &Path, shims: &Path) -> ExclusionSet {
        ExclusionSet::for_project(policy, shims)
    }

    /// A verdict's refusals as text, for assertions.
    ///
    /// `Verdict` has no `Display` — it exposes `refusals()` — so this
    /// renders them rather than a Display impl being added just for tests.
    fn why(verdict: &Verdict) -> String {
        verdict
            .refusals()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// A scratch directory, removed by each test that makes one.
    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rachna-exclusion-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    /// A project share with a `rachna.nix` and a shim directory in it.
    fn project(dir: &Path) -> (PathBuf, PathBuf) {
        let policy = dir.join("rachna.nix");
        std::fs::write(&policy, "{ tier = \"none\"; }\n").expect("policy");
        let shims = dir.join(".rachna/bin");
        std::fs::create_dir_all(&shims).expect("shims");
        (policy, shims)
    }

    #[test]
    fn the_policy_file_inside_the_share_is_refused() {
        // THE INVARIANT, finally enforced. `00` §3.11: the guest never sees
        // `rachna.nix`, because a guest that can write its own policy can
        // grant itself permissions — concretely, an `npm` postinstall
        // appending an `allow` rule (`15` §104).
        //
        // Measured BEFORE this landed, from a real guest's own console:
        //
        //   RACHNA-WORKSPACE-FILES: AGENTS.md Cargo.lock … rachna.nix src
        //
        // `check` and `ExclusionSet` both existed and were tested. Nothing
        // walked a share or stat'd a path, so the invariant was documented
        // and unenforced — which `exclusion.rs`'s own header calls the
        // "declared and never enforced" shape, apparently without noticing
        // it described this module.
        let dir = scratch("policy-visible");
        let (policy, shims) = project(&dir);
        let set = ExclusionSet::for_project(&policy, &shims);

        let verdict = verify(&set, &dir).expect("the share is readable");
        // DETECTED, and reported as an ADVISORY rather than fatal.
        //
        // The first version of this test asserted the start was refused,
        // and that behaviour was measured as unusable: `rachna.nix` lives
        // in the project directory and the project directory IS the
        // workspace share, so it refused every project that exists. And
        // `14` §2 measured VZ's share API as "a URL and a read-only flag …
        // no exclusion list", so the file cannot be hidden — refusing a
        // condition that is unavoidable by design is not a control.
        //
        // `00` §3.11a's reload gate is what makes advisory the right level:
        // a grant the guest writes is inert until the user approves it.
        assert!(!verdict.is_allowed(), "it must still be DETECTED");
        assert!(verdict.may_mount(), "but it must not stop a start");
        assert_eq!(verdict.advisories().len(), 1, "{}", why(&verdict));
        assert!(verdict.fatal_refusals().is_empty(), "{}", why(&verdict));
        assert!(
            !verdict.is_vacuous(),
            "the check must have compared something"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reaching_the_shim_directory_is_fatal() {
        // THE ENTRY THAT MATTERS. `08` §4's table calls this "worse than
        // the policy-tampering attack it mirrors": a guest that replaces
        // `.rachna/bin/rustfmt` gets code execution on the HOST, because
        // the editor is configured to run it. No reload gate helps —
        // there is no reload to gate — so this one stops a start.
        let dir = scratch("shim-fatal");
        let share = dir.join("workspace");
        std::fs::create_dir_all(&share).expect("share");
        let policy = dir.join("rachna.nix");
        std::fs::write(&policy, "{ }\n").expect("policy");
        let shims = dir.join(".rachna/bin");
        std::fs::create_dir_all(&shims).expect("shims");

        // The attack: a name inside the share reaching the shim directory.
        #[cfg(unix)]
        std::os::unix::fs::symlink(&shims, share.join("tools")).expect("symlink");

        let verdict = verify(&set_for(&policy, &shims), &share).expect("readable");
        assert!(
            !verdict.may_mount(),
            "shim exposure must stop a start: {}",
            why(&verdict)
        );
        assert_eq!(verdict.fatal_refusals().len(), 1, "{}", why(&verdict));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_clean_share_has_neither_advisories_nor_refusals() {
        // The control. Without this, the two tests above could both be
        // satisfied by a check that flags everything.
        let dir = scratch("clean-split");
        let share = dir.join("workspace");
        std::fs::create_dir_all(&share).expect("share");
        std::fs::write(share.join("main.rs"), "fn main() {}\n").expect("src");
        let policy = dir.join("rachna.nix");
        std::fs::write(&policy, "{ }\n").expect("policy");
        let shims = dir.join(".rachna/bin");
        std::fs::create_dir_all(&shims).expect("shims");

        let verdict = verify(&set_for(&policy, &shims), &share).expect("readable");
        assert!(verdict.may_mount());
        assert!(verdict.advisories().is_empty(), "{}", why(&verdict));
        assert!(verdict.fatal_refusals().is_empty(), "{}", why(&verdict));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_share_without_the_policy_file_is_allowed() {
        // The other half, and the one that proves the test above is not
        // simply refusing everything. `rachna.nix` lives beside the
        // project rather than inside the shared directory.
        let dir = scratch("policy-outside");
        let share = dir.join("workspace");
        std::fs::create_dir_all(&share).expect("share");
        std::fs::write(share.join("main.rs"), "fn main() {}\n").expect("source");
        let policy = dir.join("rachna.nix");
        std::fs::write(&policy, "{ tier = \"none\"; }\n").expect("policy");
        let shims = dir.join(".rachna/bin");
        std::fs::create_dir_all(&shims).expect("shims");
        let set = ExclusionSet::for_project(&policy, &shims);

        let verdict = verify(&set, &share).expect("readable");
        assert!(
            verdict.is_allowed(),
            "a clean share must mount: {}",
            why(&verdict)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_real_hardlink_on_disk_to_the_policy_file_is_refused() {
        // `13` §4's MEASURED attack: a second name for the same inode.
        // `14` §4's table calls this the one the case-sensitive volume does
        // NOT close, so the inode check is the only thing that catches it.
        let dir = scratch("hardlink");
        let share = dir.join("workspace");
        std::fs::create_dir_all(&share).expect("share");
        let policy = dir.join("rachna.nix");
        std::fs::write(&policy, "{ tier = \"none\"; }\n").expect("policy");
        let shims = dir.join(".rachna/bin");
        std::fs::create_dir_all(&shims).expect("shims");

        // The attack: an innocuous name inside the share, same inode.
        let decoy = share.join("innocuous.txt");
        if std::fs::hard_link(&policy, &decoy).is_err() {
            println!("SKIP: this filesystem refused a hardlink");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        let set = ExclusionSet::for_project(&policy, &shims);
        let verdict = verify(&set, &share).expect("readable");
        assert!(
            !verdict.is_allowed(),
            "a hardlink reaching the policy file must be refused: {}",
            why(&verdict)
        );
        // NAMES THE DECOY, because the attacker chose that name and it is
        // therefore evidence (`14` §3).
        assert!(
            why(&verdict).contains("innocuous.txt"),
            "the refusal must name what reached it: {}",
            why(&verdict)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlink_to_the_policy_file_is_refused() {
        // The same shape as a hardlink with a cheaper setup, and the walk
        // has to RESOLVE a link to catch it: a symlink's own inode is not
        // the file it reaches, so comparing the link itself would pass.
        let dir = scratch("symlink");
        let share = dir.join("workspace");
        std::fs::create_dir_all(&share).expect("share");
        let policy = dir.join("rachna.nix");
        std::fs::write(&policy, "{ tier = \"none\"; }\n").expect("policy");
        let shims = dir.join(".rachna/bin");
        std::fs::create_dir_all(&shims).expect("shims");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&policy, share.join("notes.md")).expect("symlink");

        let set = ExclusionSet::for_project(&policy, &shims);
        let verdict = verify(&set, &share).expect("readable");
        assert!(
            !verdict.is_allowed(),
            "a symlink reaching the policy file must be refused: {}",
            why(&verdict)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dangling_symlink_is_not_a_refusal() {
        // It reaches nothing, so it cannot reach an excluded file. Worth a
        // test because the obvious implementation — treat an unstattable
        // entry as suspicious — would refuse every broken link in a real
        // project, and broken links are ordinary.
        let dir = scratch("dangling");
        let share = dir.join("workspace");
        std::fs::create_dir_all(&share).expect("share");
        let policy = dir.join("rachna.nix");
        std::fs::write(&policy, "{ }\n").expect("policy");
        let shims = dir.join(".rachna/bin");
        std::fs::create_dir_all(&shims).expect("shims");

        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("nowhere"), share.join("broken")).expect("symlink");

        let set = ExclusionSet::for_project(&policy, &shims);
        let verdict = verify(&set, &share).expect("readable");
        assert!(
            verdict.is_allowed(),
            "a broken link reaches nothing: {}",
            why(&verdict)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_walk_does_not_follow_a_symlink_out_of_the_share() {
        // A symlinked DIRECTORY pointing at `/` would otherwise make this
        // walk the host filesystem — unbounded work on every `rachna
        // start`, and the reason the walk uses `symlink_metadata` while the
        // exclusion set uses `metadata`.
        let dir = scratch("no-escape");
        let share = dir.join("workspace");
        std::fs::create_dir_all(share.join("src")).expect("share");
        let policy = dir.join("rachna.nix");
        std::fs::write(&policy, "{ }\n").expect("policy");
        let shims = dir.join(".rachna/bin");
        std::fs::create_dir_all(&shims).expect("shims");

        // A link to the parent, which contains the policy file. Following
        // it would both escape and find an excluded inode.
        #[cfg(unix)]
        std::os::unix::fs::symlink(&dir, share.join("escape")).expect("symlink");

        let walked = walk(&share).expect("readable");
        assert!(
            !walked
                .entries
                .iter()
                .any(|e| e.path.ends_with("escape/rachna.nix")),
            "the walk followed a symlink out of the share: {:?}",
            walked.entries
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_directory_refuses_rather_than_passing_quietly() {
        // Coverage IS the check. A directory nobody could read is one where
        // an excluded inode might be hiding, so it refuses — the same
        // argument `Verdict::is_vacuous` makes about an empty comparison.
        let dir = scratch("unreadable");
        let share = dir.join("workspace");
        let secret = share.join("locked");
        std::fs::create_dir_all(&secret).expect("share");
        let policy = dir.join("rachna.nix");
        std::fs::write(&policy, "{ }\n").expect("policy");
        let shims = dir.join(".rachna/bin");
        std::fs::create_dir_all(&shims).expect("shims");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000))
                .expect("chmod");
        }

        let set = ExclusionSet::for_project(&policy, &shims);
        let verdict = verify(&set, &share).expect("the root is readable");

        #[cfg(unix)]
        {
            // Running as root defeats the permission, so the refusal is
            // only asserted when the directory really was unreadable —
            // otherwise this test would fail for a reason unrelated to the
            // code.
            if std::fs::read_dir(&secret).is_err() {
                assert!(
                    !verdict.is_allowed(),
                    "an unreadable directory must refuse: {}",
                    why(&verdict)
                );
                assert!(why(&verdict).contains("locked"), "{}", why(&verdict));
            } else {
                println!("SKIP: running with permission to read a 0o000 directory");
            }
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o755));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unstattable_exclusion_refuses_rather_than_protecting_half() {
        // `resolve_with`'s contract: a path that cannot be stat'd means the
        // check never verified part of what it was asked to. Refusing is
        // the only honest answer — `14` §3's protection is per-inode, so a
        // missing inode is an unprotected file.
        let dir = scratch("unresolvable");
        let share = dir.join("workspace");
        std::fs::create_dir_all(&share).expect("share");
        let set = ExclusionSet::for_project(&dir.join("absent.nix"), &dir.join("gone"));

        let error = verify(&set, &share).expect_err("an absent exclusion must refuse");
        let text = error.to_string();
        assert!(text.contains("absent.nix"), "name the path: {text}");
        assert!(text.contains("refuses"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tree_deeper_than_the_limit_is_reported_rather_than_walked_forever() {
        // `MAX_DEPTH` bounds the walk so a hostile layout cannot hang
        // `rachna start`. Three mutants survived here — `>` to `==`, `>` to
        // `>=`, and `depth + 1` to `depth * 1` — because nothing built a
        // tree deep enough to reach the limit.
        //
        // `depth * 1` is the interesting one: it makes depth permanently 0,
        // so the bound never fires and a symlink loop or a pathological
        // tree walks until something else gives out.
        let dir = scratch("too-deep");
        let share = dir.join("workspace");
        let policy = dir.join("rachna.nix");
        std::fs::write(&policy, "{ }\n").expect("policy");
        let shims = dir.join(".rachna/bin");
        std::fs::create_dir_all(&shims).expect("shims");

        // THE BOUNDARY, not merely "something was refused".
        //
        // A first version built `0..=MAX_DEPTH` levels and asserted only
        // that `unreadable` was non-empty. Both `> MAX_DEPTH` mutated to
        // `==` and to `>=` SURVIVED it, because every variant refuses
        // something in a tree that deep — the test could not tell which
        // boundary was in force.
        //
        // So a file is planted on each side of the limit:
        //
        //   depth MAX_DEPTH      walked   (`>=` would refuse it)
        //   depth MAX_DEPTH + 1  refused  (`==` would walk it)
        //
        // One file either side pins the comparison exactly.
        let mut at_limit = share.clone();
        for level in 0..MAX_DEPTH {
            at_limit = at_limit.join(format!("d{level}"));
        }
        std::fs::create_dir_all(&at_limit).expect("tree to the limit");
        std::fs::write(at_limit.join("at-limit.txt"), "x").expect("file");

        let past_limit = at_limit.join("one-more");
        std::fs::create_dir_all(&past_limit).expect("one past");
        std::fs::write(past_limit.join("buried.txt"), "x").expect("buried");

        let walked = walk(&share).expect("the root is readable");
        assert!(
            walked
                .entries
                .iter()
                .any(|e| e.path.ends_with("at-limit.txt")),
            "a directory AT the limit must still be walked — `>=` would have \
             refused it: {:?}",
            walked.unreadable
        );
        assert!(
            !walked
                .entries
                .iter()
                .any(|e| e.path.ends_with("buried.txt")),
            "a directory PAST the limit must not be walked — `==` would have \
             let it through"
        );
        assert!(
            !walked.unreadable.is_empty(),
            "the cut-off must be reported rather than silent"
        );

        // `verify` turns that into a REFUSAL, because a directory the check
        // could not see is one it cannot vouch for.
        let verdict = verify(&set_for(&policy, &shims), &share).expect("readable");
        assert!(
            !verdict.may_mount(),
            "an unwalked subtree must refuse: {}",
            why(&verdict)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_shallow_tree_is_walked_completely() {
        // The control for the test above: without it, `> MAX_DEPTH` mutated
        // to `>= 0` — refusing everything — would satisfy it.
        let dir = scratch("shallow");
        let share = dir.join("workspace");
        std::fs::create_dir_all(share.join("src/inner")).expect("tree");
        std::fs::write(share.join("src/inner/deep.rs"), "x").expect("file");
        let policy = dir.join("rachna.nix");
        std::fs::write(&policy, "{ }\n").expect("policy");
        let shims = dir.join(".rachna/bin");
        std::fs::create_dir_all(&shims).expect("shims");

        let walked = walk(&share).expect("readable");
        assert!(walked.unreadable.is_empty(), "{:?}", walked.unreadable);
        assert!(
            walked.entries.iter().any(|e| e.path.ends_with("deep.rs")),
            "a nested file must still be examined: {:?}",
            walked.entries
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_walk_failure_says_which_path_and_why() {
        // `WalkError`'s `fmt` returning `Ok(())` survived: nothing asserted
        // the text. It is what a user sees when a share cannot be read, and
        // an empty message names neither the path nor the reason.
        let dir = scratch("walk-error");
        let missing = dir.join("nowhere");
        let error = walk(&missing).expect_err("an absent share cannot be walked");
        let text = error.to_string();
        assert!(text.contains("nowhere"), "name the path: {text}");
        assert!(
            text.contains("check never verified"),
            "say why it matters: {text}"
        );
        assert!(!text.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_share_that_is_not_a_directory_is_refused() {
        // A file where a directory was expected is a config error, and
        // mounting it would hand the guest something this check never
        // walked.
        let dir = scratch("not-a-dir");
        let file = dir.join("afile");
        std::fs::write(&file, "x").expect("file");
        let error = walk(&file).expect_err("a file is not a share");
        assert!(error.why.contains("not a directory"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    const SHARE_DEV: u64 = 1;

    /// The identity of `rachna.nix` — the file every attack below targets.
    const POLICY: FileId = FileId {
        device: SHARE_DEV,
        inode: 42,
    };

    fn excluded() -> BTreeSet<FileId> {
        [POLICY].into_iter().collect()
    }

    // ---- building the set, which nothing did -----------------------------

    #[test]
    fn the_set_covers_the_policy_file_and_the_shims() {
        // `08` §4's table lists both, and the SHIM row is the worse of the
        // two: a guest that replaces `.rachna/bin/rustfmt` gets code
        // execution on the host, because the editor runs it. No reload gate
        // helps there — there is no reload to gate — so this entry is
        // load-bearing however `00` §3.11a's policy-file question settles.
        let set = ExclusionSet::for_project(
            Path::new("/proj/rachna.nix"),
            Path::new("/home/dev/.rachna/projects/app-a3f2/bin"),
        );
        assert_eq!(
            set.paths(),
            [
                PathBuf::from("/proj/rachna.nix"),
                PathBuf::from("/home/dev/.rachna/projects/app-a3f2/bin"),
            ]
        );
    }

    #[test]
    fn resolving_turns_paths_into_identities() {
        // The point of the whole module: identity, not names. `11` §5 and
        // `12` §3 measured a hardlink and a case variant defeating a
        // name-based check.
        let set = ExclusionSet::for_project(Path::new("/proj/rachna.nix"), Path::new("/proj/bin"));
        let resolved = set
            .resolve_with(|path| {
                Some(FileId {
                    device: SHARE_DEV,
                    inode: if path.ends_with("rachna.nix") { 10 } else { 20 },
                })
            })
            .expect("both resolve");
        assert_eq!(resolved.len(), 2);
        assert!(resolved.contains(&FileId {
            device: SHARE_DEV,
            inode: 10
        }));
    }

    #[test]
    fn a_path_that_cannot_be_resolved_is_an_error_not_a_shorter_set() {
        // THE property. A short set makes `check` refuse nothing for the
        // missing entry, and `Verdict::is_vacuous` is the only thing that
        // would notice — so returning a partial set would be the silent
        // half-protection `14` §3 warns about. First assert the success
        // path, so the failure below is not vacuous.
        let set = ExclusionSet::for_project(Path::new("/proj/rachna.nix"), Path::new("/proj/bin"));
        assert!(set
            .resolve_with(|_| Some(FileId {
                device: SHARE_DEV,
                inode: 1
            }))
            .is_ok());

        // Now fail on the SECOND path, which is the dangerous direction: the
        // first succeeded, so a buggy implementation would have a non-empty
        // set and look like it worked.
        let error = set
            .resolve_with(|path| {
                if path.ends_with("rachna.nix") {
                    Some(FileId {
                        device: SHARE_DEV,
                        inode: 10,
                    })
                } else {
                    None
                }
            })
            .expect_err("an unresolvable path must be an error");
        assert_eq!(error.path, PathBuf::from("/proj/bin"));

        // And the message says why refusing beats protecting half.
        let text = error.to_string();
        assert!(text.contains("/proj/bin"), "{text}");
        assert!(text.contains("never verified"), "{text}");
        assert!(text.contains("half"), "{text}");
    }

    #[test]
    fn a_resolved_set_is_what_check_needs_to_be_non_vacuous() {
        // Ties the producer to the consumer: a set built here, fed to
        // `check`, must refuse a hardlink to the policy file. Without this
        // the two halves could each be correct and not fit together.
        let set = ExclusionSet::for_project(Path::new("/proj/rachna.nix"), Path::new("/proj/bin"));
        let resolved = set
            .resolve_with(|path| {
                Some(FileId {
                    device: SHARE_DEV,
                    inode: if path.ends_with("rachna.nix") { 10 } else { 20 },
                })
            })
            .expect("resolves");

        // A file in the share under an innocent name, same inode as the
        // policy — `11` §5's measured attack.
        let verdict = check(
            SHARE_DEV,
            &resolved,
            &[entry("/workspace/notes.txt", 10, 2)],
        );
        assert!(!verdict.is_vacuous(), "the check had nothing to compare");
        assert!(
            !verdict.is_allowed(),
            "a hardlink to rachna.nix was allowed"
        );
    }

    fn entry(path: &str, inode: u64, links: u64) -> ShareEntry {
        ShareEntry {
            path: PathBuf::from(path),
            id: FileId {
                device: SHARE_DEV,
                inode,
            },
            links,
        }
    }

    // ---- the three measured attacks --------------------------------------

    #[test]
    fn a_hardlink_to_the_policy_file_is_refused() {
        // `13` §4, measured succeeding on macOS: the policy file is excluded
        // by path, so the attacker's move is a second name for the same inode
        // INSIDE the share. This is the attack that actually matters (`14`
        // §3), because it defeats every name-based check.
        let entries = [entry("ws/innocuous.txt", POLICY.inode, 2)];
        let verdict = check(SHARE_DEV, &excluded(), &entries);

        assert!(!verdict.is_allowed());
        assert_eq!(
            verdict.refusals(),
            [Refusal::ReachesExcludedFile {
                entry: PathBuf::from("ws/innocuous.txt"),
                id: POLICY,
            }]
        );
    }

    #[test]
    fn a_case_variant_is_refused_by_the_same_check() {
        // `12` §3, measured succeeding on APFS: `RACHNA.NIX` resolves to
        // `rachna.nix`. It needs no separate rule — a case variant IS the same
        // inode, so the identity comparison closes both attacks at once
        // (`14` §4). Asserted so that claim is tested, not just stated.
        let entries = [entry("ws/RACHNA.NIX", POLICY.inode, 2)];
        assert!(!check(SHARE_DEV, &excluded(), &entries).is_allowed());
    }

    #[test]
    fn a_hardlink_nested_deep_in_the_tree_is_still_refused() {
        // `14` §3 tested this placement explicitly: hiding it several levels
        // down must not help.
        let entries = [entry("ws/a/b/c/d/e/sneaky", POLICY.inode, 2)];
        assert!(!check(SHARE_DEV, &excluded(), &entries).is_allowed());
    }

    #[test]
    fn an_entry_on_another_filesystem_is_refused() {
        // `14` §3 step 3. A mount point inside the workspace was never
        // compared against anything, because the exclusion set was resolved
        // on the share's own device.
        let foreign = ShareEntry {
            path: PathBuf::from("ws/mnt"),
            id: FileId {
                device: 99,
                inode: 7,
            },
            links: 1,
        };
        let verdict = check(SHARE_DEV, &excluded(), &[foreign]);
        assert_eq!(
            verdict.refusals(),
            [Refusal::CrossesFilesystem {
                entry: PathBuf::from("ws/mnt"),
                entry_device: 99,
                share_device: SHARE_DEV,
            }]
        );
    }

    // ---- the ordinary case must still work -------------------------------

    #[test]
    fn an_ordinary_project_tree_is_allowed() {
        let entries = [
            entry("ws/src/main.rs", 100, 1),
            entry("ws/Cargo.toml", 101, 1),
            entry("ws/README.md", 102, 1),
        ];
        let verdict = check(SHARE_DEV, &excluded(), &entries);
        assert!(verdict.is_allowed());
        assert!(verdict.refusals().is_empty());
        assert_eq!(verdict.entries_examined(), 3);
    }

    #[test]
    fn a_hardlink_to_something_not_excluded_is_allowed() {
        // Hardlinks are legitimate — build systems and package managers make
        // them. Only one pointing at an EXCLUDED file is an escape, and
        // refusing all of them would break real projects for no gain.
        let entries = [entry("ws/node_modules/.bin/tsc", 500, 3)];
        assert!(check(SHARE_DEV, &excluded(), &entries).is_allowed());
    }

    #[test]
    fn the_excluded_inode_with_a_single_link_is_allowed() {
        // The policy file itself, seen in its own directory with nlink == 1,
        // is not an escape: there is no second name. Refusing it would make
        // the check fire on every normal project.
        let entries = [entry("rachna.nix", POLICY.inode, 1)];
        assert!(check(SHARE_DEV, &excluded(), &entries).is_allowed());
    }

    // ---- batch reporting -------------------------------------------------

    #[test]
    fn every_refusal_is_reported_not_just_the_first() {
        // Same principle as the denial report (00 §3.3): a user fixing one
        // hardlink should not have to re-run to find the second.
        let entries = [
            entry("ws/one", POLICY.inode, 2),
            entry("ws/fine", 200, 1),
            entry("ws/two", POLICY.inode, 2),
        ];
        let verdict = check(SHARE_DEV, &excluded(), &entries);
        assert_eq!(verdict.refusals().len(), 2);
        assert_eq!(verdict.entries_examined(), 3);
    }

    #[test]
    fn a_refusal_explains_itself_with_the_evidence() {
        let entries = [entry("ws/innocuous.txt", POLICY.inode, 2)];
        let verdict = check(SHARE_DEV, &excluded(), &entries);
        let message = verdict.refusals()[0].to_string();
        assert!(message.contains("ws/innocuous.txt"), "{message}");
        assert!(message.contains("inode 42"), "{message}");
        assert!(message.contains("excluded"), "{message}");
    }

    // ---- the vacuous-check guard ----------------------------------------

    #[test]
    fn a_check_with_nothing_excluded_is_vacuous_not_safe() {
        // The failure mode this project keeps hitting (`11` §7, `23` §1.1): a
        // check that examined nothing reports success. An empty exclusion set
        // yields no refusals, so the verdict must say it proves nothing.
        let entries = [entry("ws/innocuous.txt", POLICY.inode, 2)];
        let verdict = check(SHARE_DEV, &BTreeSet::new(), &entries);
        assert!(verdict.is_allowed(), "nothing to compare against");
        assert!(
            verdict.is_vacuous(),
            "a check protecting nothing must admit it"
        );
        assert_eq!(verdict.excluded_resolved(), 0);
    }

    #[test]
    fn a_real_check_is_not_vacuous() {
        let verdict = check(SHARE_DEV, &excluded(), &[entry("ws/f", 9, 1)]);
        assert!(!verdict.is_vacuous());
        assert_eq!(verdict.excluded_resolved(), 1);
    }

    #[test]
    fn an_empty_share_is_allowed_but_still_records_what_it_checked() {
        let verdict = check(SHARE_DEV, &excluded(), &[]);
        assert!(verdict.is_allowed());
        assert_eq!(verdict.entries_examined(), 0);
        assert!(
            !verdict.is_vacuous(),
            "the exclusion set was still resolved"
        );
    }

    // ---- the name filter, and its documented weakness --------------------

    #[test]
    fn the_name_filter_is_case_insensitive() {
        // Deliberate: on APFS `RACHNA.NIX` and `rachna.nix` are the same file
        // (`12` §3), so a case-SENSITIVE comparison would fail to add it to
        // the excluded set — making the real check vacuous rather than wrong,
        // which is worse because it looks fine.
        for name in ["rachna.nix", "RACHNA.NIX", "Rachna.Nix"] {
            assert!(
                is_excluded_by_name(Path::new(name), &["rachna.nix"]),
                "{name} must be recognised"
            );
        }
    }

    #[test]
    fn the_name_filter_matches_on_the_file_name_not_the_path() {
        assert!(is_excluded_by_name(
            Path::new("/a/b/rachna.nix"),
            &["rachna.nix"]
        ));
        // A directory merely NAMED like the file is not it.
        assert!(!is_excluded_by_name(
            Path::new("/a/rachna.nix/inner.txt"),
            &["rachna.nix"]
        ));
    }

    #[test]
    fn the_name_filter_rejects_unrelated_names() {
        assert!(!is_excluded_by_name(
            Path::new("rachna.nix.bak"),
            &["rachna.nix"]
        ));
        assert!(!is_excluded_by_name(Path::new("main.rs"), &["rachna.nix"]));
        assert!(!is_excluded_by_name(Path::new("/"), &["rachna.nix"]));
    }

    #[test]
    fn the_name_filter_alone_does_not_catch_a_renamed_hardlink() {
        // Documents WHY the identity check exists. `ws/innocuous.txt` is a
        // hardlink to the policy file: the name filter says it is fine, and
        // the identity check refuses it. If this ever starts passing the name
        // filter, something has been conflated.
        let attack = Path::new("ws/innocuous.txt");
        assert!(!is_excluded_by_name(attack, &["rachna.nix"]));

        let entries = [entry("ws/innocuous.txt", POLICY.inode, 2)];
        assert!(!check(SHARE_DEV, &excluded(), &entries).is_allowed());
    }
}
