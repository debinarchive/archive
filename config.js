window.DEBIN_CONFIG = {
  // Данные вашего репозитория на GitHub:
  // Если ещё не настроил, оставь "YOUR_GITHUB_USERNAME" — включится локальный демо-режим.
  GITHUB: {
    owner: "YOUR_GITHUB_USERNAME",
    repo: "DebinArchive",
    branch: "main"
  },

  // Сюда вставь строки из Colab-генератора (Ячейка 6):
  ENCRYPTED_TOKEN: "",
  CREATOR_PASS_HASH: "",

  // Лимит обычных участников (не считая Создателя Miralys). Поставь null, если без лимита.
  MAX_REGULAR_USERS: 5,

  // Максимальный размер видео/файла через GitHub API (в МБ)
  MAX_UPLOAD_MB: 25
};