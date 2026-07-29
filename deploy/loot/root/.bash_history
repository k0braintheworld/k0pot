ls -la
cat /etc/os-release
uname -a
docker ps
cd /opt/acme
git pull
vi .env
mysql -u acme_app -p'Pr0d_9xQZ!ktm2024' acme_prod -e 'select count(*) from users;'
export AWS_ACCESS_KEY_ID=AKIA7ACMEQK2NR0PZ3XV
aws s3 sync s3://acme-prod-backups /opt/acme/backup --profile prod
sshpass -p 'B@ckup_nas3!7z' ssh svc_backup@10.0.0.9
crontab -l
curl -s -H "Authorization: Bearer k0tok_7Fq3Rn9ZbW1sYpX" https://api.acme-corp.example/v1/health
df -h
exit
