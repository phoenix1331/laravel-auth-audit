<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Requests;

use Illuminate\Foundation\Http\FormRequest;

class NonScopedFormRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->isAdmin();
    }

    public function rules(): array
    {
        return [];
    }
}
