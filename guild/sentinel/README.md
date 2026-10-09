# tringuyen~sentinel

Incident responder for a compromised CI credential in AWS IAM. When a Sentinel integration is connected, it cites Semgrep findings from the CI scan and then reads the open incident. It does not invent evidence ids, and it does not execute dangerous actions such as deleting the IAM user.
