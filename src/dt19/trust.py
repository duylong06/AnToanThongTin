"""Trust list có phiên bản và luân chuyển khóa.

Người phụ trách: Long | Tuần: 5

Phải có trong tệp này:
- TrustEntry: key_id, valid_from, valid_to
- TrustList: is_trusted(key_id, moment), load(), save(), latest_in()
- KeyRotationService: publish_initial(), rotate(), revoke_in_trust_list()

Điểm mấu chốt: is_trusted xét THỜI ĐIỂM KÝ, không xét hiện tại.
"""

# TODO
