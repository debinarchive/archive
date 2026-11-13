window.DEBIN_CONFIG = {
  // Данные вашего репозитория на GitHub:
  // Если ещё не настроил, оставь "YOUR_GITHUB_USERNAME" — включится локальный демо-режим.
  GITHUB: {
    owner: "YOUR_GITHUB_USERNAME",
    repo: "DebinArchive",
    branch: "main"
  },

  // Сюда вставь строки из Colab-генератора (Ячейка 6):
  ENCRYPTED_TOKEN: "H9oINKAlKXSKpQLt7RkJvPB5wqURFf0ufYzJ1VoVonsQvdI2tGnThQ9/4BXvlOkYe13CIkcZAJwucPs6kfjigjDE0wPQtvep+lBala5S6WGa8hfld+xFmGDS3zze+oSMk6+gHhfDJjJslJq0idM=",
  CREATOR_PASS_HASH: "6c3ce1b0fb7ff29d184ce992294a9fb9cc45a36f5c2650b7208d57bf6fdf768a",

  // Лимит обычных участников (не считая Создателя Miralys). Поставь null, если без лимита.
  MAX_REGULAR_USERS: 5,

  // Максимальный размер видео/файла через GitHub API (в МБ)
  MAX_UPLOAD_MB: 25
};
