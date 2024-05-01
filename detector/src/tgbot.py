import asyncio
from aiogram import Bot, Dispatcher, types
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.dispatcher import FSMContext
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from main import settings
from ip import info, blocker, whitelist
from util.logger import log

# Здесь мы создаём объекты `Bot` и `Dispatcher` для работы с Telegram.
bot = Bot(token=settings.telegram_bot_token)
dp = Dispatcher(bot, storage=MemoryStorage())


# Функция для отправки сообщения в Telegram.
async def send_ddos_notification(ip: str = ""):
    # Сохраняем IP в хранилище бота.
    await dp.storage.set_data(chat=settings.your_telegram_id, data={"ip": ip})

    # Отправляем уведомление пользователю.
    await bot.send_message(
        chat_id=settings.your_telegram_id,
        text=f"⚠️ Зафиксирована DoS/DDoS-атака!\n\nИнформация об IP:\n\n{info.get_readable(ip, filter_keys=['readme'])}\n\nХотите ли вы заблокировать этот IP?",
        reply_markup=get_inline_keyboard(),
    )
    log.debug("Уведомление о DoS/DDoS-атаке отправлено в Telegram.")


# Обработчик нажатий на кнопки в сообщении.
@dp.callback_query_handler()
async def on_confirmation(callback_query: types.CallbackQuery, state: FSMContext):
    # Пользователь выбирает, что делать с IP.
    choice = callback_query.data

    # Получаем IP из хранилища.
    ip = str((await dp.storage.get_data(chat=settings.your_telegram_id)).get("ip"))

    # Делаем что-то в зависимости от выбора пользователя.
    if choice == "block":
        blocker.block(ip)
        await bot.send_message(
            chat_id=callback_query.message.chat.id, text="🚫✅ IP заблокирован!"
        )
    elif choice == "whitelist":
        whitelist.add(ip)
        await bot.send_message(
            chat_id=callback_query.message.chat.id, text="📝✅ IP разрешен!"
        )

    # Удаляем кнопки, поскольку они больше не нужны.
    await bot.edit_message_reply_markup(
        chat_id=callback_query.message.chat.id,
        message_id=callback_query.message.message_id,
        reply_markup=None,
    )

    # Очищаем состояние бота.
    await state.finish()


# Здесь мы создаём кнопки для сообщения.
def get_inline_keyboard():
    keyboard = InlineKeyboardMarkup()
    keyboard.add(
        InlineKeyboardButton("🚫 Заблокировать", callback_data="block"),
        InlineKeyboardButton("📝 Разрешить", callback_data="whitelist"),
    )
    return keyboard


# Здесь мы запускаем бота.
async def start_bot():
    log.debug("Запускаем Telegram-бота...")
    await dp.start_polling()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    asyncio.ensure_future(start_bot())
    loop.run_forever()
