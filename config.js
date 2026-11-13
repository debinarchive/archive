window.DEBIN_CONFIG = {
  // Данные вашего репозитория на GitHub:
  // Если ещё не настроил, оставь "YOUR_GITHUB_USERNAME" — включится локальный демо-режим.
  GITHUB: {
    owner: "debinarchive",
    repo: "archive",
    branch: "main"
  },

  // Сюда вставь строки из Colab-генератора (Ячейка 6):
  ENCRYPTED_TOKEN: "LOQTmZb3v4wM1g4wv43FtUzUvVT25YFgme0DoNW0TXSKP3nV8Lo5X0gBi6t2YgWs2+oYAeZZ9GHz",
  CREATOR_PASS_HASH: "6c3ce1b0fb7ff29d184ce992294a9fb9cc45a36f5c2650b7208d57bf6fdf768a",

  // Лимит обычных участников (не считая Создателя Miralys). Поставь null, если без лимита.
  MAX_REGULAR_USERS: null,

  // Максимальный размер видео/файла через GitHub API (в МБ)
  MAX_UPLOAD_MB: 10000
};
