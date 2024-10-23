# 1.0.0
## Added
- Initial Release.
- The Forescout plugin fetches hosts and their risk information from All Hosts page of Forescout. It does not support any actions on Forescout. Netskope normalization score calculation for OT Security Risk Score and CYSIV Risk Score => ((Forescout Score - Min Forescout) / (Max Forescout - Min Forescout)) * (Max Netskope - Min Netskope) + Min Netskope