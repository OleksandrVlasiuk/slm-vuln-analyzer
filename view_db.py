from sqlalchemy.orm import Session
from database import engine, ScanSession


def check_database():
    with Session(engine) as session:
        scans = session.query(ScanSession).all()

        if not scans:
            print("База даних порожня.")
            return

        print(f"[*] Знайдено сесій сканування: {len(scans)}\n")

        for s in scans:
            print("=" * 50)
            print(f"Сесія #{s.id} | Тип: {s.scan_type} | Дата: {s.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 50)

            for vuln in s.vulnerabilities:
                print(f"  Вразливість: {vuln.rule_id}")
                print(f"  Файл: {vuln.file_path}")

                if vuln.ai_explanation:
                    xai = vuln.ai_explanation
                    print(f"  Модель: {xai.model_name}")
                    print(f"  Час генерації: {round(xai.inference_time, 2)} сек")
                    print(f"  Уривок пояснення:\n{xai.explanation_text[:150]}...\n")
                else:
                    print("  Пояснення ШІ відсутнє\n")


if __name__ == "__main__":
    check_database()