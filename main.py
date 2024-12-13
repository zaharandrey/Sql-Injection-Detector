import re


class SQLInjectionDetector:
    """
    Модуль для виявлення та фільтрації SQL-ін'єкцій у вхідних даних.
    """

    # Ознаки SQL-ін'єкції: ключові слова, символи тощо
    SQL_PATTERNS = [
        r"(?:')",  # Одинарна лапка
        r"(?:--)",  # Два дефіси (SQL-коментарі)
        r"(?:#)",  # Решітка (коментарі)
        r"(?:\\bSELECT\\b)",  # Ключове слово SELECT
        r"(?:\\bINSERT\\b)",  # Ключове слово INSERT
        r"(?:\\bUPDATE\\b)",  # Ключове слово UPDATE
        r"(?:\\bDELETE\\b)",  # Ключове слово DELETE
        r"(?:\\bDROP\\b)",  # Ключове слово DROP
        r"(?:\\bUNION\\b)",  # Ключове слово UNION
    ]

    @staticmethod
    def check_input(data: str) -> bool:
        """
        Перевіряє вхідний рядок на наявність SQL-ін'єкцій.

        :param data: Рядок для аналізу.
        :return: True, якщо виявлено потенційно шкідливий вміст, інакше False.
        """
        for pattern in SQLInjectionDetector.SQL_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def sanitize_input(data: str) -> str:
        """
        Очищує вхідний рядок від небезпечних символів.

        :param data: Рядок для очищення.
        :return: Очищений рядок.
        """
        sanitized = re.sub(r"['"";\\-\\-\\#]", "", data)  # Видаляємо небезпечні символи
        return sanitized

    def analyze(self, data: str):
        """
        Аналізує вхідний рядок на SQL-ін'єкції та фільтрує його.

        :param data: Вхідний рядок.
        :return: None
        """
        if self.check_input(data):
            print("Попередження: Виявлено можливу SQL-ін'єкцію!")
        else:
            print("Дані безпечні.")

        sanitized_data = self.sanitize_input(data)
        print(f"Очищені дані: {sanitized_data}")


# Демонстрація використання модуля
data_samples = [
    "SELECT * FROM users WHERE username = 'admin' --",
    "Hello, world!",
    "DROP TABLE users;",
    "name=John#email=john@example.com"
]

sql_detector = SQLInjectionDetector()
for sample in data_samples:
    print(f"Аналіз даних: {sample}")
    sql_detector.analyze(sample)
    print("-")

