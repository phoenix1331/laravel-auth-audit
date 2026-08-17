<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Requests;

use Illuminate\Foundation\Http\FormRequest;

class BareFormRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [];
    }
}
