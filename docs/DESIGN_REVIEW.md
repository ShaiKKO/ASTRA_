# ASTRA_ Design Review: Pushing the Boundaries of Agentic Development

_A critical analysis of the current design with enhancement recommendations for achieving world-class agentic development capabilities._

**Date:** 2026-02-02  
**Status:** FINALIZED - Ready for Implementation Plan Update  
**Goal:** Identify opportunities to enhance ASTRA_ beyond current state-of-the-art

---

## Executive Summary

The current ASTRA_ design is solid and addresses many fundamental challenges in multi-agent orchestration. However, to truly push the boundaries of agentic development and achieve "world-class" status, several enhancement areas have been identified. This review documents **14 enhancement areas** and the **finalized design decisions** for implementation.

**Key Finding:** The current design excels at _orchestration_ and _safety_ but lacks mechanisms for _learning_, _reasoning_, and _intelligent context management_ that would enable agents to improve over time and handle increasingly complex tasks.

---

## Finalized Design Decisions

| Question                          | Decision                 | Rationale                                                                     |
| --------------------------------- | ------------------------ | ----------------------------------------------------------------------------- |
| **Learning Scope**                | Full strategy evolution  | Agents should learn and improve across all dimensions over time               |
| **Reasoning Integration**         | Implicit in capabilities | Maintains modular architecture; reasoning patterns are capabilities           |
| **Context Intelligence Location** | Separate service         | Follows single responsibility; can scale/swap independently                   |
| **Quality Dimensions**            | User-configurable        | Different use cases (MVP speed vs enterprise quality) need different settings |
| **Implementation Timing**         | Update current plan      | Full integration into v1 implementation plan                                  |

---

## Part 1: Design Strengths (What's Working Well)

### 1.1 Capability-Based Composition ✅

The decision to move from fixed agent roles to composable capabilities is forward-thinking:

```
Traditional: Fixed Agents → "Developer", "Tester", "Reviewer"
ASTRA_:       Capabilities  → Repo.Read + Build.Build + Test.UnitTest → Custom Agent
```

**Why this matters:** Enables infinite agent configurations without code changes.

### 1.2 Hybrid Workflow Model ✅

The DAG + Safe Chaos Zones concept elegantly solves the fundamental tradeoff:

| Approach         | Pros                   | Cons                      |
| ---------------- | ---------------------- | ------------------------- |
| Pure DAG         | Predictable, auditable | Rigid, slow               |
| Pure Swarm       | Fast, creative         | Chaotic, unreliable       |
| **ASTRA_ Hybrid** | Best of both           | Complexity in transitions |

### 1.3 Pluggable Architecture ✅

The abstraction layers for Context, Persistence, and Model Gateway are well-designed:

- **Context**: memory → sqlite → vector → git
- **Persistence**: filesystem → git → sqlite → postgres
- **Gateway**: OpenAI → Anthropic → Local → Custom

### 1.4 First-Class Guardrails ✅

Policy, Budget, Sandbox, and Redaction integrated from the start. The 5-tier sandbox model is well thought out.

### 1.5 Comprehensive Contracts ✅

CapabilityContract schema with side effects, preconditions, postconditions, and validation levels.

---

## Part 2: Enhancement Specifications

### 2.1 Experience & Learning Service 🔴 CRITICAL

**Decision:** Full strategy evolution - agents learn and improve across all dimensions.

**Purpose:** Enable agents to improve over time based on outcomes, not just execute statically.

**Components:**

```rust
// New crate: astra-experience

/// Core experience tracking and learning service
pub struct ExperienceService {
    /// Track outcomes by capability + task type
    outcome_tracker: OutcomeTracker,

    /// Learn which capabilities work for which tasks
    capability_learner: CapabilityEffectivenessLearner,

    /// Learn optimal team compositions
    team_learner: TeamCompositionLearner,

    /// Learn and refine prompt strategies
    prompt_evolver: PromptStrategyEvolver,

    /// Learn task decomposition patterns
    decomposition_learner: DecompositionPatternLearner,
}

pub trait ExperienceProvider {
    /// Record an outcome for learning
    fn record_outcome(&self, run: &RunReport) -> Result<(), AstraError>;

    /// Get capability recommendations for a task
    fn recommend_capabilities(&self, task: &TaskEnvelope) -> Vec<CapabilityRecommendation>;

    /// Get team composition recommendations
    fn recommend_team(&self, goal: &str, constraints: &Constraints) -> TeamRecommendation;

    /// Get decomposition recommendations
    fn recommend_decomposition(&self, task: &TaskEnvelope) -> DecompositionRecommendation;

    /// Get prompt strategy for a capability + task type
    fn get_prompt_strategy(&self, capability: &str, task_type: &str) -> PromptStrategy;

    /// Export learned strategies (for backup/transfer)
    fn export_strategies(&self) -> Result<StrategyExport, AstraError>;

    /// Import strategies (from another instance)
    fn import_strategies(&self, strategies: StrategyExport) -> Result<(), AstraError>;
}

/// Tracks what worked and what didn't
pub struct OutcomeRecord {
    pub run_id: String,
    pub task_type: String,
    pub capabilities_used: Vec<String>,
    pub team_composition: TeamComposition,
    pub prompt_strategies: HashMap<String, String>,
    pub decomposition_pattern: DecompositionPattern,
    pub outcome: OutcomeMetrics,
    pub quality_scores: QualityScores,
    pub duration: Duration,
    pub tokens_used: u64,
    pub cost: f64,
}

/// Recommendation with confidence and reasoning
pub struct CapabilityRecommendation {
    pub capability_id: String,
    pub confidence: f32,
    pub reason: String,
    pub historical_success_rate: f32,
    pub average_quality_score: f32,
}

/// Strategy that evolves over time
pub struct PromptStrategy {
    pub strategy_id: String,
    pub version: u32,
    pub template: String,
    pub success_rate: f32,
    pub sample_count: u32,
    pub last_updated: DateTime<Utc>,
}
```

**Learning Mechanisms:**

1. **Capability Effectiveness**: Track success/failure rates by capability + task type. Use Bayesian updating.
2. **Team Composition**: Learn which agent combinations work for which problem classes.
3. **Prompt Evolution**: A/B test prompt variations, promote winners.
4. **Decomposition Patterns**: Learn how to break down tasks based on successful decompositions.

**Storage:** Uses persistence service for durable storage of learned strategies.

---

### 2.2 Reasoning Capabilities 🔴 CRITICAL

**Decision:** Implicit in capabilities - reasoning patterns are implemented as capabilities.

**Purpose:** Provide structured reasoning beyond black-box LLM calls.

**New Capabilities to Implement:**

```python
# capabilities/reasoning/ - New capability module

class ChainOfThoughtCapability(CapabilityPlugin):
    """Execute step-by-step reasoning with explicit trace."""

    @property
    def contract(self) -> CapabilityContract:
        return CapabilityContract(
            id="Reasoning.ChainOfThought",
            name="Chain of Thought Reasoning",
            inputs={"problem": "string", "context": "object"},
            outputs={
                "reasoning_steps": "array",
                "conclusion": "string",
                "confidence": "number"
            },
            side_effects=SideEffects(effects=[], scope=[]),
        )


class SelfReflectionCapability(CapabilityPlugin):
    """Generate output, critique it, refine it."""

    @property
    def contract(self) -> CapabilityContract:
        return CapabilityContract(
            id="Reasoning.SelfReflection",
            name="Self Reflection",
            inputs={"task": "string", "initial_output": "string"},
            outputs={
                "critique": "string",
                "refined_output": "string",
                "improvements_made": "array"
            },
            side_effects=SideEffects(effects=[], scope=[]),
        )


class DebateCapability(CapabilityPlugin):
    """Multi-perspective debate for complex decisions."""

    @property
    def contract(self) -> CapabilityContract:
        return CapabilityContract(
            id="Reasoning.Debate",
            name="Multi-Perspective Debate",
            inputs={
                "question": "string",
                "perspectives": "array",  # Different viewpoints to argue
                "context": "object"
            },
            outputs={
                "arguments": "array",
                "synthesis": "string",
                "recommendation": "string",
                "confidence": "number"
            },
            side_effects=SideEffects(effects=[], scope=[]),
        )


class ConfidenceCalibrationCapability(CapabilityPlugin):
    """Assess and express confidence in outputs."""

    @property
    def contract(self) -> CapabilityContract:
        return CapabilityContract(
            id="Reasoning.ConfidenceCalibration",
            name="Confidence Calibration",
            inputs={"claim": "string", "evidence": "array"},
            outputs={
                "confidence": "number",
                "uncertainty_factors": "array",
                "evidence_quality": "number",
                "recommendation": "string"  # proceed/seek_help/escalate
            },
            side_effects=SideEffects(effects=[], scope=[]),
        )


class IterativeRefinementCapability(CapabilityPlugin):
    """Iteratively improve output until criteria met."""

    @property
    def contract(self) -> CapabilityContract:
        return CapabilityContract(
            id="Reasoning.IterativeRefinement",
            name="Iterative Refinement",
            inputs={
                "initial": "string",
                "criteria": "array",
                "max_iterations": "integer"
            },
            outputs={
                "final_output": "string",
                "iterations": "array",
                "criteria_met": "object",
                "converged": "boolean"
            },
            side_effects=SideEffects(effects=[], scope=[]),
        )
```

**Rust Support Types:**

```rust
// In astra-types

/// Reasoning trace for auditability
pub struct ReasoningTrace {
    pub capability_id: String,
    pub steps: Vec<ReasoningStep>,
    pub confidence: f32,
    pub duration: Duration,
}

pub struct ReasoningStep {
    pub step_number: u32,
    pub thought: String,
    pub action: Option<String>,
    pub observation: Option<String>,
    pub confidence_delta: f32,
}

/// Attached to Outcome when reasoning capabilities used
pub struct ReasoningMetadata {
    pub pattern_used: String,
    pub trace: ReasoningTrace,
    pub alternatives_considered: Vec<Alternative>,
}
```

---

### 2.3 Context Intelligence Service 🔴 CRITICAL

**Decision:** Separate service - follows single responsibility, can scale independently.

**Purpose:** Add intelligence layer on top of basic context storage.

**Architecture:**

```
Agent ──┬──► Context Intelligence ──► Context Service ──► Backends
        │         (optional)
        └──► Context Service ──► Backends (direct, if intelligence disabled)
```

**Components:**

```rust
// New crate: astra-context-intel

/// Intelligent context layer on top of Context Service
pub struct ContextIntelligenceService {
    /// Underlying context service
    context: Arc<dyn ContextProvider>,

    /// Relevance scoring model
    relevance_scorer: Box<dyn RelevanceScorer>,

    /// Context compression
    compressor: Box<dyn ContextCompressor>,

    /// Knowledge graph builder
    knowledge_graph: KnowledgeGraph,

    /// Contradiction detector
    contradiction_detector: Box<dyn ContradictionDetector>,

    /// Usage tracker (for learning what's actually useful)
    usage_tracker: UsageTracker,
}

pub trait ContextIntelligenceProvider {
    /// Get relevant context for a task, ranked by relevance
    fn get_relevant_context(
        &self,
        task: &TaskEnvelope,
        max_tokens: usize,
    ) -> Result<RankedContext, AstraError>;

    /// Compress context while preserving essential information
    fn compress_context(
        &self,
        items: Vec<ContextItem>,
        target_tokens: usize,
        preserve_priority: Vec<String>,  // IDs that must be kept
    ) -> Result<CompressedContext, AstraError>;

    /// Detect contradictions in context
    fn detect_contradictions(
        &self,
        scope: ContextScope,
    ) -> Result<Vec<Contradiction>, AstraError>;

    /// Build/update knowledge graph
    fn update_knowledge_graph(
        &self,
        items: Vec<ContextItem>,
    ) -> Result<(), AstraError>;

    /// Query knowledge graph for related items
    fn get_related(
        &self,
        item_id: &str,
        max_hops: u32,
    ) -> Result<Vec<RelatedItem>, AstraError>;

    /// Record what context was actually used (for learning)
    fn record_usage(
        &self,
        task_id: &str,
        used_item_ids: Vec<String>,
        outcome: &Outcome,
    ) -> Result<(), AstraError>;

    /// Check freshness and mark stale items
    fn check_freshness(
        &self,
        scope: ContextScope,
    ) -> Result<FreshnessReport, AstraError>;
}

/// Context with relevance scores
pub struct RankedContext {
    pub items: Vec<RankedContextItem>,
    pub total_tokens: usize,
    pub truncated: bool,
    pub relevance_explanation: String,
}

pub struct RankedContextItem {
    pub item: ContextItem,
    pub relevance_score: f32,
    pub relevance_factors: Vec<RelevanceFactor>,
}

pub enum RelevanceFactor {
    TaskSimilarity(f32),
    Recency(f32),
    AuthorRelevance(f32),
    KnowledgeGraphDistance(f32),
    HistoricalUsage(f32),
}

/// Compressed context with metadata
pub struct CompressedContext {
    pub summary: String,
    pub key_facts: Vec<String>,
    pub preserved_items: Vec<ContextItem>,
    pub compression_ratio: f32,
    pub information_loss_estimate: f32,
}

/// Detected contradiction
pub struct Contradiction {
    pub item_a: String,
    pub item_b: String,
    pub description: String,
    pub severity: ContradictionSeverity,
    pub suggested_resolution: Option<String>,
}

pub enum ContradictionSeverity {
    Critical,  // Must be resolved before proceeding
    Warning,   // Should be noted
    Info,      // Minor inconsistency
}
```

**Integration with Experience Service:**

- Usage tracking feeds into Experience Service for learning what context is actually useful
- Relevance scoring improves over time based on usage data

---

### 2.4 Enhanced Workflow Nodes 🟡 HIGH IMPACT

**Purpose:** More expressive workflow primitives matching real development patterns.

**New Node Types:**

```rust
// Extensions to astra-orchestrator

pub enum WorkflowNode {
    // === EXISTING ===
    Task(TaskNode),
    ChaosZone(ChaosZoneNode),
    Checkpoint(CheckpointNode),
    Join(JoinNode),

    // === NEW: Control Flow ===

    /// Execute different paths based on outcome
    Conditional {
        /// Condition to evaluate
        condition: Condition,
        /// Node to execute if true
        if_true: Box<WorkflowNode>,
        /// Node to execute if false (optional)
        if_false: Option<Box<WorkflowNode>>,
    },

    /// Retry with configurable backoff
    RetryLoop {
        /// Node to retry
        body: Box<WorkflowNode>,
        /// Maximum retry attempts
        max_attempts: u32,
        /// Backoff policy between retries
        backoff: BackoffPolicy,
        /// Condition that determines if retry is needed
        retry_condition: Condition,
    },

    /// Wait for human approval before proceeding
    HumanApproval {
        /// Prompt shown to human
        prompt: String,
        /// What to show for review
        artifacts_to_review: Vec<String>,
        /// Timeout before auto-action
        timeout: Option<Duration>,
        /// Action if timeout (proceed/abort/escalate)
        timeout_action: TimeoutAction,
        /// Required role for approval (optional)
        required_role: Option<String>,
    },

    /// Iterative refinement loop (generate → validate → fix)
    RefinementLoop {
        /// Generate initial output
        generate: Box<WorkflowNode>,
        /// Validate output
        validate: Box<WorkflowNode>,
        /// Fix issues found
        fix: Box<WorkflowNode>,
        /// Maximum iterations
        max_iterations: u32,
        /// Success criteria (stops loop when met)
        success_criteria: Condition,
    },

    /// Try multiple strategies in parallel, select best
    ParallelExplore {
        /// Different strategies to try
        strategies: Vec<Box<WorkflowNode>>,
        /// How to select the winner
        selection_criteria: SelectionCriteria,
        /// Maximum parallel executions
        max_parallel: usize,
        /// Stop other strategies when one succeeds?
        early_termination: bool,
    },

    /// Exit workflow early when condition met
    EarlyExit {
        /// Node to execute
        body: Box<WorkflowNode>,
        /// Condition that triggers early exit
        exit_condition: Condition,
        /// What to return on early exit
        exit_outcome: ExitOutcome,
    },

    /// Time-bounded execution with escalation
    TimeBounded {
        /// Node to execute
        body: Box<WorkflowNode>,
        /// Time limit
        time_limit: Duration,
        /// What to do on timeout
        timeout_action: TimeoutEscalation,
    },
}

/// How to select from parallel exploration results
pub enum SelectionCriteria {
    /// First one to succeed wins
    FirstSuccess,
    /// Best quality score wins
    BestScore { scorer: String },
    /// Majority agreement required
    Consensus { threshold: f32 },
    /// Human makes final choice
    HumanChoice { prompt: String },
    /// Combine/ensemble results
    Ensemble { combiner: String },
}

/// Backoff policy for retries
pub enum BackoffPolicy {
    /// Fixed delay between retries
    Fixed { delay: Duration },
    /// Exponential backoff
    Exponential { initial: Duration, multiplier: f32, max: Duration },
    /// No delay
    Immediate,
}

/// Condition for flow control
pub enum Condition {
    /// Check outcome status
    OutcomeStatus(OutcomeStatus),
    /// Check artifact exists
    ArtifactExists(String),
    /// Check quality score threshold
    QualityAbove { dimension: String, threshold: f32 },
    /// Check test pass rate
    TestsPass { threshold: f32 },
    /// Custom expression
    Expression(String),
    /// Combine conditions
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),
}
```

---

### 2.5 Quality Assurance Service 🟡 HIGH IMPACT

**Decision:** User-configurable quality dimensions and thresholds.

**Purpose:** Multi-dimensional quality scoring with regression detection.

```rust
// New crate: astra-quality

/// Quality assurance service
pub struct QualityAssuranceService {
    /// Registered quality scorers
    scorers: Vec<Box<dyn QualityScorer>>,

    /// Quality history for regression detection
    history: QualityHistory,

    /// User-configured quality profile
    profile: QualityProfile,

    /// A/B testing framework
    ab_testing: ABTestingFramework,
}

/// User-configurable quality profile
pub struct QualityProfile {
    pub name: String,

    /// Which dimensions to measure
    pub dimensions: Vec<QualityDimensionConfig>,

    /// Overall quality calculation
    pub aggregation: AggregationMethod,

    /// Minimum thresholds for passing
    pub thresholds: HashMap<String, f32>,

    /// Regression sensitivity
    pub regression_sensitivity: f32,
}

pub struct QualityDimensionConfig {
    pub dimension: QualityDimension,
    pub enabled: bool,
    pub weight: f32,
    pub scorer: String,  // Which scorer to use
}

/// Built-in quality dimensions (user can enable/disable)
pub enum QualityDimension {
    /// Does it work correctly?
    Correctness,
    /// Does it address all requirements?
    Completeness,
    /// Is it easy to maintain?
    Maintainability,
    /// Is it efficient?
    Performance,
    /// Is it secure?
    Security,
    /// Is it well tested?
    TestCoverage,
    /// Is it documented?
    Documentation,
    /// How readable is the code?
    Readability,
    /// Custom dimension
    Custom(String),
}

pub trait QualityScorer: Send + Sync {
    /// Score an artifact
    fn score(&self, artifact: &Artifact, context: &QualityContext) -> Result<DimensionScore, AstraError>;

    /// Which dimension this scores
    fn dimension(&self) -> QualityDimension;

    /// Scorer identifier
    fn id(&self) -> &str;
}

pub struct QualityScore {
    pub overall: f32,
    pub dimensions: HashMap<String, DimensionScore>,
    pub profile_used: String,
    pub passed_thresholds: bool,
    pub failed_dimensions: Vec<String>,
}

pub struct DimensionScore {
    pub dimension: String,
    pub score: f32,
    pub confidence: f32,
    pub explanation: String,
    pub suggestions: Vec<String>,
}

/// Preset quality profiles
impl QualityProfile {
    /// Fast iteration, minimal checks
    pub fn mvp_speed() -> Self { /* ... */ }

    /// Balanced quality and speed
    pub fn balanced() -> Self { /* ... */ }

    /// High quality, thorough checks
    pub fn quality_first() -> Self { /* ... */ }

    /// Enterprise/large codebase
    pub fn enterprise() -> Self { /* ... */ }

    /// Security-focused
    pub fn security_critical() -> Self { /* ... */ }
}
```

**Preset Profiles:**

| Profile             | Focus           | Dimensions Emphasized                     |
| ------------------- | --------------- | ----------------------------------------- |
| `mvp_speed`         | Fast iteration  | Correctness only                          |
| `balanced`          | General use     | Correctness, Tests, Basic maintainability |
| `quality_first`     | High quality    | All dimensions, higher thresholds         |
| `enterprise`        | Large codebases | Maintainability, Documentation, Tests     |
| `security_critical` | Security focus  | Security, Correctness, Tests              |

---

### 2.6 Semantic Verification 🟡 HIGH IMPACT

**Purpose:** Verification beyond syntax - does it actually do what was intended?

```rust
// New crate: astra-semantic

pub trait SemanticVerifier: Send + Sync {
    /// Verify that changes match the stated intent
    fn verify_intent(
        &self,
        goal: &str,
        changes: &ChangeSet,
        context: &VerificationContext,
    ) -> Result<IntentVerification, AstraError>;

    /// Verify invariants are preserved
    fn verify_invariants(
        &self,
        invariants: &[Invariant],
        before: &Snapshot,
        after: &Snapshot,
    ) -> Result<InvariantVerification, AstraError>;

    /// Generate semantic diff (what does change mean?)
    fn semantic_diff(
        &self,
        before: &Artifact,
        after: &Artifact,
    ) -> Result<SemanticDiff, AstraError>;
}

pub struct IntentVerification {
    pub matches_intent: bool,
    pub confidence: f32,
    pub addressed_aspects: Vec<AddressedAspect>,
    pub unaddressed_aspects: Vec<String>,
    pub unexpected_changes: Vec<UnexpectedChange>,
    pub explanation: String,
}

pub struct AddressedAspect {
    pub aspect: String,
    pub how_addressed: String,
    pub confidence: f32,
}

pub struct UnexpectedChange {
    pub change: String,
    pub risk_level: RiskLevel,
    pub explanation: String,
}

pub struct SemanticDiff {
    /// What behaviors were added
    pub additions: Vec<BehaviorChange>,
    /// What behaviors were removed
    pub removals: Vec<BehaviorChange>,
    /// What behaviors were modified
    pub modifications: Vec<BehaviorChange>,
    /// Overall semantic summary
    pub summary: String,
}

pub struct BehaviorChange {
    pub description: String,
    pub location: String,
    pub impact: ImpactLevel,
    pub related_requirements: Vec<String>,
}
```

---

### 2.7 Model Intelligence Service 🟢 IMPORTANT

**Purpose:** Smart model selection and optimization.

```rust
// Extension to astra-gateway

pub struct ModelIntelligenceService {
    /// Model capability profiles
    profiles: HashMap<ModelId, ModelProfile>,

    /// Task-to-model matching
    matcher: Box<dyn TaskModelMatcher>,

    /// Cost/quality optimizer
    optimizer: CostQualityOptimizer,

    /// Model-specific prompting strategies
    prompt_strategies: HashMap<ModelId, PromptingStrategy>,

    /// Performance history
    performance_history: ModelPerformanceHistory,
}

pub struct ModelProfile {
    pub id: ModelId,
    pub provider: String,
    pub capabilities: ModelCapabilities,
    pub cost_per_1k_tokens: CostStructure,
    pub latency_p50: Duration,
    pub latency_p95: Duration,
    pub context_window: usize,
    pub strengths: Vec<TaskType>,
    pub weaknesses: Vec<TaskType>,
    pub prompting_hints: PromptingHints,
}

pub trait TaskModelMatcher: Send + Sync {
    /// Recommend models for a task with reasoning
    fn recommend_models(
        &self,
        task: &TaskEnvelope,
        constraints: &ModelConstraints,
    ) -> Vec<ModelRecommendation>;
}

pub struct ModelConstraints {
    pub max_cost: Option<f64>,
    pub max_latency: Option<Duration>,
    pub required_capabilities: Vec<String>,
    pub preferred_providers: Vec<String>,
    pub quality_priority: f32,  // 0.0 = cost priority, 1.0 = quality priority
}

pub struct ModelRecommendation {
    pub model_id: ModelId,
    pub score: f32,
    pub reason: String,
    pub estimated_cost: f64,
    pub estimated_quality: f32,
    pub estimated_latency: Duration,
}
```

---

### 2.8 Additional Capabilities (Implicit in Capabilities)

Since reasoning is implicit in capabilities, these additional capabilities should be added:

**Communication/Collaboration Capabilities:**

```python
class BlackboardPostCapability(CapabilityPlugin):
    """Post to shared blackboard for collaborative problem solving."""
    id = "Collaboration.BlackboardPost"

class BlackboardReadCapability(CapabilityPlugin):
    """Read from shared blackboard."""
    id = "Collaboration.BlackboardRead"

class ConsensusCapability(CapabilityPlugin):
    """Reach consensus among multiple agents."""
    id = "Collaboration.Consensus"
```

**Explainability Capabilities:**

```python
class ExplainDecisionCapability(CapabilityPlugin):
    """Explain why a decision was made."""
    id = "Explainability.ExplainDecision"

class GenerateAlternativesCapability(CapabilityPlugin):
    """Generate and explain alternative approaches."""
    id = "Explainability.GenerateAlternatives"
```

**Security Capabilities:**

```python
class DetectInjectionCapability(CapabilityPlugin):
    """Detect potential prompt injection."""
    id = "Security.DetectInjection"

class ValidateOutputCapability(CapabilityPlugin):
    """Validate output for harmful content."""
    id = "Security.ValidateOutput"

class DetectHallucinationCapability(CapabilityPlugin):
    """Detect potential hallucination in claims."""
    id = "Security.DetectHallucination"
```

---

## Part 3: New Crates Required

```
crates/
├── astra-experience/          # Learning and adaptation
│   ├── src/
│   │   ├── lib.rs
│   │   ├── tracker.rs         # Outcome tracking
│   │   ├── learner.rs         # Pattern learning algorithms
│   │   ├── recommender.rs     # Recommendations based on learning
│   │   ├── prompt_evolution.rs # Prompt strategy evolution
│   │   └── storage.rs         # Persistence of learned strategies
│   └── Cargo.toml
│
├── astra-context-intel/       # Context intelligence (separate from context)
│   ├── src/
│   │   ├── lib.rs
│   │   ├── relevance.rs       # Relevance scoring
│   │   ├── compression.rs     # Context compression
│   │   ├── knowledge_graph.rs # Relationship tracking
│   │   ├── contradiction.rs   # Contradiction detection
│   │   ├── freshness.rs       # Staleness tracking
│   │   └── usage.rs           # Usage tracking for learning
│   └── Cargo.toml
│
├── astra-quality/             # Quality assurance
│   ├── src/
│   │   ├── lib.rs
│   │   ├── scorer.rs          # Scoring framework
│   │   ├── dimensions.rs      # Quality dimensions
│   │   ├── profiles.rs        # Preset and custom profiles
│   │   ├── regression.rs      # Regression detection
│   │   ├── history.rs         # Quality history tracking
│   │   └── ab_testing.rs      # A/B testing framework
│   └── Cargo.toml
│
└── astra-semantic/            # Semantic verification
    ├── src/
    │   ├── lib.rs
    │   ├── intent.rs          # Intent verification
    │   ├── invariant.rs       # Invariant preservation
    │   ├── diff.rs            # Semantic diff
    │   └── behavior.rs        # Behavior analysis
    └── Cargo.toml
```

**New Python Capability Modules:**

```
capabilities/src/astra_capabilities/
├── reasoning/                 # Reasoning capabilities
│   ├── __init__.py
│   ├── chain_of_thought.py
│   ├── self_reflection.py
│   ├── debate.py
│   ├── confidence.py
│   └── refinement.py
│
├── collaboration/             # Collaboration capabilities
│   ├── __init__.py
│   ├── blackboard.py
│   └── consensus.py
│
├── explainability/            # Explainability capabilities
│   ├── __init__.py
│   ├── explain_decision.py
│   └── alternatives.py
│
└── security/                  # Security capabilities
    ├── __init__.py
    ├── injection_detection.py
    ├── output_validation.py
    └── hallucination_detection.py
```

---

## Part 4: Updated Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         INTELLIGENCE LAYER (NEW)                         │
├───────────────┬───────────────┬─────────────────┬───────────────────────┤
│   Experience  │    Context    │     Quality     │      Semantic         │
│    Service    │  Intelligence │   Assurance     │    Verification       │
│  (learning)   │   (smart ctx) │  (scoring/AB)   │   (intent verify)     │
└───────┬───────┴───────┬───────┴────────┬────────┴───────────┬───────────┘
        │               │                │                    │
        ▼               ▼                ▼                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                           CORE LAYER (EXISTING)                           │
├───────────────┬───────────────┬────────────────┬────────────┬────────────┤
│  Orchestrator │  Agent Kernel │    Context     │ Persistence │  Gateway   │
│   (enhanced   │  (+ reasoning │    Service     │   Service   │ (+ model   │
│   workflows)  │  capabilities)│               │             │  intel)    │
└───────────────┴───────────────┴────────────────┴────────────┴────────────┘
        │               │                │                    │
        ▼               ▼                ▼                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                         SAFETY LAYER (EXISTING)                           │
├───────────────┬───────────────┬────────────────┬────────────────────────┤
│    Policy     │    Sandbox    │    Budget      │      Redaction         │
│  Enforcement  │    Manager    │  Enforcement   │      (secrets)         │
└───────────────┴───────────────┴────────────────┴────────────────────────┘
```

---

## Part 5: Implementation Priority

### Milestone Mapping

| Enhancement                 | New Issues            | Target Milestone     |
| --------------------------- | --------------------- | -------------------- |
| **Experience Service**      | #107-#114 (8 issues)  | New M9: Intelligence |
| **Reasoning Capabilities**  | #115-#120 (6 issues)  | M6 extension         |
| **Context Intelligence**    | #121-#127 (7 issues)  | M2 extension         |
| **Enhanced Workflow Nodes** | #128-#134 (7 issues)  | M4 extension         |
| **Quality Assurance**       | #135-#140 (6 issues)  | New M9: Intelligence |
| **Semantic Verification**   | #141-#145 (5 issues)  | M3 extension         |
| **Model Intelligence**      | #146-#150 (5 issues)  | M5 extension         |
| **Additional Capabilities** | #151-#160 (10 issues) | M6 extension         |

**Total New Issues: 54**
**Updated Total: 106 + 54 = 160 issues**

### Critical Path

```
M0 (Foundation)
    ↓
M1 (Core Runtime)
    ↓
M2 (Infrastructure) ←── Context Intelligence integration
    ↓
M3 (Policy & Sandbox) ←── Semantic Verification integration
    ↓
M4 (Orchestration) ←── Enhanced Workflow Nodes
    ↓
M5 (Model Gateway) ←── Model Intelligence integration
    ↓
M6 (Capabilities) ←── Reasoning + Collaboration + Security capabilities
    ↓
M7 (Observability)
    ↓
M8 (Validation)
    ↓
M9 (Intelligence) ←── NEW: Experience Service + Quality Assurance
```

---

## Part 6: Risk Assessment

| Enhancement            | Complexity | Risk                 | Mitigation                                              |
| ---------------------- | ---------- | -------------------- | ------------------------------------------------------- |
| Experience Service     | High       | Learning instability | Start with simple tracking, add evolution incrementally |
| Context Intelligence   | High       | Performance overhead | Async processing, caching, optional enablement          |
| Reasoning Capabilities | Medium     | Over-engineering     | Start with CoT, add patterns based on need              |
| Workflow Nodes         | Low        | Edge cases           | Thorough testing of all node types                      |
| Quality Assurance      | Medium     | Subjectivity         | Focus on objective metrics first                        |
| Semantic Verification  | High       | Accuracy             | Use as advisory, not blocking initially                 |
| Model Intelligence     | Medium     | Maintenance burden   | Auto-learning from outcomes                             |

---

## Conclusion

With these finalized decisions:

1. **Full strategy evolution** for learning
2. **Capabilities-based reasoning** for modularity
3. **Separate Context Intelligence service** for clean architecture
4. **User-configurable quality** for flexibility
5. **Full integration** into v1 plan

ASTRA_ will be positioned as a truly world-class agentic development framework that:

- **Learns and improves** over time (not just executes)
- **Reasons explicitly** (not just generates)
- **Manages context intelligently** (not just stores)
- **Measures quality comprehensively** (not just tests)
- **Verifies intent semantically** (not just syntax)

The implementation plan should now be updated with the 54 new issues organized into the appropriate milestones.

---

_Document Status: FINALIZED - Ready for Implementation Plan Update_
