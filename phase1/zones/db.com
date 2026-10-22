$ORIGIN com.
$TTL 300

@ IN SOA ns.com. hostmaster.com. (
    2026102201
    3600
    600
    86400
    300
)

@       IN NS ns.com.
ns      IN A 172.16.3.20

example IN NS ns.example.com.
ns.example IN A 172.16.3.30
