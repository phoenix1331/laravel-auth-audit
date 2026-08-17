<?php

namespace Phoenix1331\LaravelAuthAudit\Scanning;

use Phoenix1331\LaravelAuthAudit\Attributes\WithoutAuthAudit;
use Phoenix1331\LaravelAuthAudit\Data\RouteEntry;
use Phoenix1331\LaravelAuthAudit\Data\RouteStatus;
use ReflectionClass;
use ReflectionException;
use ReflectionMethod;

class AttributeResolver
{
    public function resolve(RouteEntry $entry): RouteEntry
    {
        if ($entry->status === RouteStatus::Skipped) {
            return $entry;
        }

        if ($entry->controller === null) {
            return $entry;
        }

        try {
            $ref = new ReflectionClass($entry->controller);
        } catch (ReflectionException) {
            return $entry;
        }

        if ($bypass = $this->readAttribute($ref)) {
            return $this->applyBypass($entry, $bypass);
        }

        if ($entry->action === null) {
            return $entry;
        }

        try {
            $method = $ref->getMethod($entry->action);
        } catch (ReflectionException) {
            return $entry;
        }

        if ($bypass = $this->readAttribute($method)) {
            return $this->applyBypass($entry, $bypass);
        }

        return $entry;
    }

    private function readAttribute(ReflectionClass|ReflectionMethod $reflector): ?WithoutAuthAudit
    {
        $attributes = $reflector->getAttributes(WithoutAuthAudit::class);

        if ($attributes === []) {
            return null;
        }

        return $attributes[0]->newInstance();
    }

    private function applyBypass(RouteEntry $entry, WithoutAuthAudit $attribute): RouteEntry
    {
        if ($attribute->isExpired()) {
            $entry->status = RouteStatus::Unauthorised;
            $entry->skipReason = null;
            $entry->antiPattern = 'expired-bypass: '.$attribute->reason;

            return $entry;
        }

        $entry->status = RouteStatus::Skipped;
        $entry->skipReason = $attribute->reason;

        return $entry;
    }
}
