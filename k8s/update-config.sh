kubectl apply -f deployment-main.yaml -n algo2fa
kubectl rollout restart deployment/algo2fa-web-main-deployment -n algo2fa
