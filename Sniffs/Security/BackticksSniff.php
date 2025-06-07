<?php
/**
 * WordPress Coding Standard.
 *
 * @package WPCS\WordPressCodingStandards
 * @link    https://github.com/WordPress/WordPress-Coding-Standards
 * @license https://opensource.org/licenses/MIT MIT
 */

namespace ET\ElegantThemes\Sniffs\Security;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Flag usage of backticks in PHP code which automatically gets converted to shell_exec calls.
 *
 * @package WPCS\WordPressCodingStandards
 * @since   1.0.0
 */
class BackticksSniff implements Sniff {

    /**
     * Returns the token types that this sniff is interested in.
     *
     * @return array(int)
     */
    public function register() {
        return [T_BACKTICK];
    }

    /**
     * Processes the tokens that this sniff is interested in.
     *
     * @param File $phpcsFile The file where the token was found.
     * @param int  $stackPtr  The position in the stack where the token was found.
     *
     * @return void
     */
    public function process(File $phpcsFile, $stackPtr) {
        $tokens = $phpcsFile->getTokens();
        
        // Find the closing backtick
        $closer = $phpcsFile->findNext(T_BACKTICK, $stackPtr + 1);
        if (!$closer) {
            return;
        }

        // Get the content between backticks
        $content = '';
        for ($i = $stackPtr + 1; $i < $closer; $i++) {
            $content .= $tokens[$i]['content'];
        }

        $error = 'Usage of backticks is not allowed as it gets converted to shell_exec() calls. This can be a security risk.';
        $phpcsFile->addError($error, $stackPtr, 'BackticksNotAllowed');
    }
} 