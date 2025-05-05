The error in the image indicates a failure during a Helm upgrade due to an issue with the external-secrets webhook:

Error: UPGRADE FAILED: cannot patch "docker-genci-prc-internal-svc-secret-store" with kind ExternalSecret: Internal error occurred: failed calling webhook...

Root Cause:

The Helm upgrade is trying to apply changes to an ExternalSecret resource, but the external-secrets-webhook service is unavailable or not ready:

no endpoints available for service "external-secrets-webhook"

How to Fix:

1. Check the external-secrets webhook service: Run:

kubectl get svc -n <namespace> | grep external-secrets
kubectl get endpoints -n <namespace> external-secrets-webhook

This confirms if the webhook service has active endpoints.


2. Check the Pods: Ensure the webhook pod is running:

kubectl get pods -n <namespace> | grep external-secrets


3. Restart the Webhook (if needed): If the pod is stuck or crashlooping, delete it to restart:

kubectl delete pod <external-secrets-pod-name> -n <namespace>


4. Check Webhook Configurations: Misconfigured or missing webhook settings in MutatingWebhookConfiguration or ValidatingWebhookConfiguration might cause this.



Would you like a quick command script to auto-check all of these?

