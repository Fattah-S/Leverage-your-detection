from .builder import BuilderNode
from .coverage import CoverageNode
from .health import RuleHealthNode
from .intel import ThreatIntelNode
from .noise import NoiseTuningNode
from .posture import PostureNode
from .review import EngineerReviewNode
from .validation import ValidationNode


def all_nodes(bus) -> list:
    return [ThreatIntelNode(), CoverageNode(), RuleHealthNode(), NoiseTuningNode(), BuilderNode(),
            ValidationNode(), EngineerReviewNode(), PostureNode(bus)]
