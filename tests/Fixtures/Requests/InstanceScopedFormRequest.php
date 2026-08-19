<?php

namespace Phoenix1331\LaravelAuthAudit\Tests\Fixtures\Requests;

use Illuminate\Foundation\Http\FormRequest;

class InstanceScopedFormRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->route('order'));
    }

    public function rules(): array
    {
        return [];
    }
}
