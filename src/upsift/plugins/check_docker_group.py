import grp, getpass
from upsift.checks.base import BaseCheck, Finding

class DockerGroupCheck(BaseCheck):
    id = "docker_group"
    name = "User in docker group"
    severity = "high"
    description = "Users in the 'docker' group can gain root on the host by mounting the filesystem via containers."

    def run(self):
        findings = []
        user = getpass.getuser()
        try:
            docker = grp.getgrnam("docker")
            if user in docker.gr_mem:
                findings.append(Finding(
                    id=self.id,
                    title=f"User '{user}' is in docker group",
                    severity="high",
                    description=self.description,
                    evidence=f"Group members: {docker.gr_mem}",
                    remediation="Remove non-admins from docker group or use rootless Docker with strict controls.",
                    references=["https://docs.docker.com/engine/security/"],
                ))
        except KeyError:
            pass
        return findings
