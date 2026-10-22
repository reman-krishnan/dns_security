$ORIGIN example.com.
$TTL 300
@ IN SOA ns.example.com. hostmaster.example.com. (
    2026102201 3600 600 86400 300 )
@   IN NS ns.example.com.
ns  IN A 172.16.3.30
; advertised
@   IN A 172.16.1.20
www IN A 172.16.1.20
; unadvertised internal service hosts (the targets of the walk)
backup IN A 172.16.1.41
dev    IN A 172.16.1.42
git    IN A 172.16.1.43
mail   IN A 172.16.1.44
vpn    IN A 172.16.1.45
