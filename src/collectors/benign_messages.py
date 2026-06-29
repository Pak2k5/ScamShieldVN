"""Curated benign Vietnamese message collector."""

import uuid
from datetime import datetime, timezone

from loguru import logger

from src.collectors.base import BaseCollector
from src.models.enums import RecordType
from src.models.record import RawRecord


class BenignMessagesCollector(BaseCollector):
    """Produces curated benign (non-scam) Vietnamese message records.
    
    These serve as negative examples for scam text classification.
    Includes: OTP warnings, delivery notifications, bank education, promotions.
    Synthetic messages are marked synthetic=True with evidence_level capped at B.
    """

    # Curated benign messages by type
    MESSAGES = {
        "otp_warning": [
            "Mã OTP của bạn là 456789. Tuyệt đối không cung cấp mã này cho bất kỳ ai kể cả nhân viên ngân hàng.",
            "Mã xác thực giao dịch: 123456. Lưu ý: Ngân hàng không bao giờ yêu cầu bạn đọc mã OTP qua điện thoại.",
            "OTP xác nhận đăng nhập: 987654. Mã có hiệu lực 5 phút. Không chia sẻ mã này với ai.",
            "Mã bảo mật 234567 để xác nhận thay đổi mật khẩu. Nếu bạn không thực hiện, vui lòng liên hệ hotline.",
            "Mã OTP 345678 cho giao dịch chuyển khoản. Không cung cấp OTP cho người khác dưới bất kỳ hình thức nào.",
        ],
        "delivery_notification": [
            "Đơn hàng #VN12345678 của bạn đã được giao thành công. Cảm ơn bạn đã mua sắm!",
            "Kiện hàng của bạn đang được vận chuyển. Dự kiến giao trong 2-3 ngày làm việc.",
            "Shipper đang trên đường giao hàng cho bạn. Vui lòng giữ điện thoại để nhận cuộc gọi.",
            "Đơn hàng Shopee #SP987654 đã xuất kho. Theo dõi tại: app Shopee > Đơn mua.",
            "Bưu phẩm EMS của bạn đã đến bưu cục. Vui lòng mang CMND/CCCD đến nhận trong 7 ngày.",
        ],
        "bank_education": [
            "Ngân hàng không bao giờ yêu cầu khách hàng cung cấp mật khẩu hoặc OTP qua điện thoại.",
            "Để bảo mật tài khoản, hãy đổi mật khẩu định kỳ và không sử dụng WiFi công cộng khi giao dịch.",
            "Cảnh báo: Không bấm vào link lạ trong tin nhắn. Luôn truy cập ngân hàng qua app chính thức.",
            "Hướng dẫn bảo mật: Kích hoạt xác thực 2 bước để bảo vệ tài khoản ngân hàng trực tuyến.",
            "Lưu ý: SMS từ ngân hàng luôn từ tên thương hiệu, không từ số điện thoại cá nhân.",
        ],
        "promotion": [
            "Flash Sale hôm nay: Giảm 50% toàn bộ sản phẩm điện tử. Áp dụng đến 23:59.",
            "Ưu đãi thành viên: Tích lũy 500 điểm nhận voucher 100K. Chi tiết tại app.",
            "Mừng sinh nhật khách hàng! Tặng bạn mã giảm giá 20% cho đơn hàng tiếp theo: BIRTHDAY20",
            "Gói cước 4G siêu tiết kiệm: 3GB/ngày chỉ 77K/tháng. Đăng ký soạn V77 gửi 191.",
            "Chương trình khách hàng thân thiết: Hoàn 10% cho mọi giao dịch thanh toán qua app.",
        ],
        "system_notification": [
            "Tài khoản của bạn đã đăng nhập thành công từ thiết bị mới. Nếu không phải bạn, đổi mật khẩu ngay.",
            "Cập nhật ứng dụng phiên bản mới 3.5.0 để trải nghiệm tính năng bảo mật nâng cao.",
            "Bảo trì hệ thống: Dịch vụ ngân hàng điện tử tạm ngưng từ 00:00-04:00 ngày 15/01.",
            "Giao dịch chuyển khoản 500,000 VNĐ đã thực hiện thành công. Số dư: 2,345,000 VNĐ.",
            "Nhắc nhở: Hạn thanh toán thẻ tín dụng của bạn là ngày 25 hàng tháng.",
        ],
    }

    def collect(self) -> list[RawRecord]:
        """Generate curated benign message records."""
        records = []
        collection_time = datetime.now(timezone.utc)

        for msg_type, messages in self.MESSAGES.items():
            for text in messages:
                record = RawRecord(
                    source_id=self.source.source_id,
                    collection_timestamp=collection_time,
                    record_type=RecordType.MESSAGE,
                    message_id=str(uuid.uuid4()),
                    text_sanitized=text,
                    benign_message_type=msg_type,
                    synthetic=True,  # These are curated/synthetic examples
                    source_type_field="manually_curated",
                    human_reviewed=True,  # Manually curated = reviewed
                )
                records.append(record)

        logger.info("Generated {} curated benign messages across {} types.",
                    len(records), len(self.MESSAGES))
        return records
