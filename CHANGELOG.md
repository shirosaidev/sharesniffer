# sharesniffer Change Log

## [0.1-b.6] = 2018-06-14
### changed
- removed "s" from --host-timeout nmap arg string
### fixed
- spaces between nmap args

## [0.1-b.5] = 2018-06-12
### added
- Nmap 7.70 support
### changed
- removed scripts (nse) files and folder and used nmap ones in paths /usr/local/share/nmap/scripts or /usr/share/nmap/scripts
### fixed
- bug with nmap nse scripts not being located

## [0.1-b.4] = 2018-06-11
### added
- more debugging output when using --debug

## [0.1-b.3] = 2018-06-08
### changed
- moved nmap nse scripts required into scripts folder
### added
- nmapdatadir for required nse scripts
### fixed
- bug with nse scripts not being found
