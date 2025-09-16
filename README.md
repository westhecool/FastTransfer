# FastTrasfer

A script to quickly and safely share files over the World Wide Web using Cloudflare http tunnels with AES-GCM encryption.

## How to use:

### Requirements

You will need to have [nodejs](https://nodejs.org) installed.

### CLI usage

To start sharing files run this command: (if using powershell replace "curl" with "irm")
```sh
curl https://ts.westhedev.xyz | node - share [files-to-share]
```
You will be given a trasfer code that can be used like this:
```sh
curl https://ts.westhedev.xyz | node - <transfer-code>
```

#### Local only mode

If you only want to share localy on your network (not over a cloudflare tunnel) add "--local" to the end of the share command.

## TODOs
- [ ] Add a web client
- [ ] Add reverse server mode