<?php

declare(strict_types=1);

namespace Rector\Rules;

use PhpParser\Node;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeTraverser;
use Rector\Rector\AbstractRector;

final class RemovePhpseclibTestCasePolyfillMethodsRector extends AbstractRector
{
    public function getNodeTypes(): array
    {
        return [ClassMethod::class];
    }

    public function refactor(Node $node)
    {
        switch ($this->getName($node)) {
            case 'assertIsArray':
            case 'assertIsString':
            case 'assertStringContainsString':
            case 'assertStringNotContainsString':
                return NodeTraverser::REMOVE_NODE;
        }

        return null;
    }
}
