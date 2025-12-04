# SMF Config
## Require check
1. createPdr.pdi.sourceInterface
2. createPdr.pdi.localFT
3. createFar.fp.outerHeader.ip
4. QFIs
## PDR
- createPdr
    - pdfId: unique ID
    - pdi
        - sourceInterface
            - type: where the packet come from, 0 = n3, 2 = n6
        - localFT: Flow Temaplate to match UE session
            - teid_start: Tunnel Endpoint ID start
            - teid_end
            - ip
                - v4: UPF's N3 IP (pdi_local_teid_ip in the code)
        - qfi: QFI ID
        - userEquipment
            - ip
                - v4: not so sure, but should be UE IP range
        - sdf
            - description: criteria for packet matching
        - farId
        - urrIds
        - qerIds
## FAR
- createFar
    - farId: FAR ID
    - fp
        - outerHeader
            - ip
                - v4: gNB N3 IP
        - outerHeader
            - teid
## URR
- createUrr
    - urrId: URR ID
    - volumeQuota
        - totalVolume: Total quota in bytes
## QER
- createQer
    - qurId: QER ID
    - maxBitRate
        - ulMBR: MBR in kbps
        - dlMBR
    - qfi        