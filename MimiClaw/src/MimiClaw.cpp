#include "MimiClaw.h"

bool MimiClaw::begin()
{
    return mimi_init() == ESP_OK;
}

bool MimiClaw::start()
{
    return mimi_start() == ESP_OK;
}

void MimiClaw::loop()
{
    mimi_loop();
}
