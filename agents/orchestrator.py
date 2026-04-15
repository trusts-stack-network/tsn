"""TSN Orchestrator — Build monitor (passive).

DISABLED: Ce service est desactivated. Le pre-commit hook cargo check
prevents henceforth les commits qui cassent le build.
ARCHITECT et NEXUS manage la repair si necessary.

L'ancien orchestrateur created des dizaines de tasks "Build casse"
en loop car Qwen3.5 local ne pouvait pas repair du Rust complexe.
"""

import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [ORCHESTRATOR] %(message)s'
)
logger = logging.getLogger('orchestrator')


def main():
    logger.info("Orchestrator DISABLED — pre-commit hook handles build validation")
    logger.info("Use ARCHITECT or NEXUS for build repair")
    sys.exit(0)


if __name__ == '__main__':
    main()
