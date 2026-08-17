<?php

namespace Phoenix1331\LaravelAuthAudit\Data;

enum RouteStatus: string
{
    case Authorised = 'authorised';
    case Unauthorised = 'unauthorised';
    case Partial = 'partial';
    case Skipped = 'skipped';
}
