# DNS Configuration for Defense

## Types of attacks to defend against

- DDOS/DOS
- Cache Poisoning
- DNS Amplification Attacks


### Mitigations against DNS Amplification Attacks

#### Disable recursion
Go modify the `/etc/bind/named.conf.options` file and add or modify the following lins:
```shell
options{
    recursion no;
};
```
With this we should be able to prevent our server from resolving queries for domains it's not authoritative for.

#### Limit the zone transfers
- What are zones?
   Zones are a way to divide the domain name space into manageable sections. Zones are used to delegate authority over a subset of the domain name space to other nameservers.
- Zone transfers are the process of replicating the DNS database from the primary server to the secondary server.

Here's how to limit zone transfers:

Go modify `/etc/bind/named.conf.local` and add the following lines:
```shell
zone "example.com" {
    type master;
    file "example.com.db";
    allow-transfer {x}; # x is any trusted IP address
    };
```

#### Set Response Rate Limiting
  
This should help us calm down the amount of traffic that can be sent to our server. This is done by setting the `rate-limit` option in the `/etc/bind/named.conf.options` file.

Here's what to add:
    ```shell

        recursion no;

        rate-limit {
                responses-per-second 5;
                window 5;
                log-only no;
                slip 10;
        };

    ```

With that set, it should help mitigate DNS amplification attacks by reducing how many responses we send to clients. Here's what each of the options does:
- `responses-per-second` - This is the number of responses we send per second.
- `window` - This is the time frame in seconds that we send the responses.
- `log-only` - This is a boolean value that determines if we log the rate limiting or not.
- `log-only no` - This means we log the rate limiting.

Other options that can be set in rate-limit are:
- `ipv4-prefix-length` - This is the length of the prefix for the IPv4 address. It takes an int
- `ipv6-prefix-length` - This is the length of the prefix for the IPv6 address. It takes an int
- `exempt-clients` - This is a list of IP addresses that are exempt from rate limiting. It takes a list of IP addresses.
- `errors-per-second` - This is the number of errors we send per second. It takes an int.
- `all-per-second` - This is the number of responses we send per second. It takes an int.
- `nodata-per-second` - This is the number of nodata responses we send per second. It takes an int. So the number of *empty* responses we send for a valid domain name
- `nxdomains-per-second` - This is the number of responses we send per second. It takes an int. So the number of responses we send for a domain that doesn't exist.
- `referrals-per-second` - This is the number of referrals we send per second. It takes an int. So the number of responses we send for a domain that we don't have the answer for.
- `qps-scale` - This is the number of queries per second we scale the rate limiting to. It takes an int. If the queries per second exceeds qps-scale's value, it reduces responses-per-second, errors-per-second, nxdomains-per-second, and all-per-second values by the ration fo the current rate to the qps-scale. So if the scale is 250 and response-per-second is 20, if 1000 qps is reached the effective responses/second will be reduced to 5.
- `max-table-size` - This is the maximum size of the rate limiting table. It takes an int.
- `min-table-size` - This is the minimum size of the rate limiting table. It takes an int.
- `slip` - This is the number of "slipped" responses to minimize the use of forged source addresses. I *think* default is 2. If we set it to 0, it does not "slip" and no small responses are sent. 1 will cause every response to slip. 

#### Check if it worked

Run `named-checkconf` to check if the configuration is correct. If it is nto correct, you'll see an error message.