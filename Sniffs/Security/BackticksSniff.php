<?php
/**
 * WordPress Coding Standard for Backticks.
 *
 * @package WPCS\WordPressCodingStandards
 * @link    https://github.com/WordPress/WordPress-Coding-Standards
 * @license https://opensource.org/licenses/MIT MIT
 */

namespace ET\ElegantThemes\Sniffs\Security;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Backticks detection with better error handling and auto-fixing.
 *
 * @package WPCS\WordPressCodingStandards
 * @since   1.0.0
 */
class ImprovedBackticksSniff implements Sniff
{
    /**
     * Track processed backticks to avoid duplicate errors.
     *
     * @var array
     */
    private $processedBackticks = [];

    /**
     * Returns the token types that this sniff is interested in.
     *
     * @return array<int>
     */
    public function register()
    {
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
    public function process(File $phpcsFile, $stackPtr)
    {
        // Reset processed backticks for each file
        $filename = $phpcsFile->getFilename();
        if (!isset($this->processedBackticks[$filename])) {
            $this->processedBackticks[$filename] = [];
        }

        // Skip if already processed
        if (in_array($stackPtr, $this->processedBackticks[$filename], true)) {
            return;
        }

        $tokens = $phpcsFile->getTokens();

        // Check if backtick is inside a string (shouldn't trigger)
        if ($this->isInsideString($phpcsFile, $stackPtr)) {
            return;
        }

        // Find the closing backtick
        $closer = $this->findClosingBacktick($phpcsFile, $stackPtr);
        
        if ($closer === false) {
            $error = 'Unclosed backtick found. This will cause a parse error and is a security risk.';
            $phpcsFile->addError($error, $stackPtr, 'UnclosedBacktick');
            return;
        }

        // Mark both backticks as processed
        $this->processedBackticks[$filename][] = $stackPtr;
        $this->processedBackticks[$filename][] = $closer;

        // Get the command content
        $content = $this->getBacktickContent($phpcsFile, $stackPtr, $closer);
        
        // Create detailed error message
        $command = trim($content);
        if (empty($command)) {
            $error = 'Empty backticks found. Use shell_exec() with proper validation instead.';
        } else {
            $error = sprintf(
                'Backticks execute shell command "%s". Use shell_exec() with proper sanitization instead.',
                $this->truncateCommand($command)
            );
        }

        // Add fixable error
        $fix = $phpcsFile->addFixableError($error, $stackPtr, 'BackticksNotAllowed');
        
        if ($fix === true) {
            $this->applyAutoFix($phpcsFile, $stackPtr, $closer, $content);
        }
    }

    /**
     * Check if backtick is inside a string literal.
     *
     * @param File $phpcsFile The file being processed.
     * @param int  $stackPtr  The position of the backtick.
     *
     * @return bool
     */
    private function isInsideString(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        
        // Look backwards for string delimiters
        $stringTokens = [T_CONSTANT_ENCAPSED_STRING, T_DOUBLE_QUOTED_STRING, T_HEREDOC, T_NOWDOC];
        
        for ($i = $stackPtr - 1; $i >= 0; $i--) {
            if (in_array($tokens[$i]['code'], $stringTokens, true)) {
                return true;
            }
            // Stop at statement boundaries
            if ($tokens[$i]['code'] === T_SEMICOLON || $tokens[$i]['line'] < $tokens[$stackPtr]['line']) {
                break;
            }
        }
        
        return false;
    }

    /**
     * Find the matching closing backtick.
     *
     * @param File $phpcsFile The file being processed.
     * @param int  $stackPtr  The position of the opening backtick.
     *
     * @return int|false The position of the closing backtick or false if not found.
     */
    private function findClosingBacktick(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $opener = $stackPtr;
        
        // Find next backtick on the same logical line or nearby lines
        for ($i = $stackPtr + 1; $i < $phpcsFile->numTokens; $i++) {
            if ($tokens[$i]['code'] === T_BACKTICK) {
                return $i;
            }
            
            // Stop searching if we've gone too far
            if ($tokens[$i]['line'] > $tokens[$opener]['line'] + 5) {
                break;
            }
        }
        
        return false;
    }

    /**
     * Get content between backticks.
     *
     * @param File $phpcsFile The file being processed.
     * @param int  $opener    The opening backtick position.
     * @param int  $closer    The closing backtick position.
     *
     * @return string
     */
    private function getBacktickContent(File $phpcsFile, $opener, $closer)
    {
        if ($closer <= $opener + 1) {
            return '';
        }
        
        return $phpcsFile->getTokensAsString($opener + 1, $closer - $opener - 1);
    }

    /**
     * Truncate command for error message.
     *
     * @param string $command The command to truncate.
     *
     * @return string
     */
    private function truncateCommand($command)
    {
        $maxLength = 50;
        if (strlen($command) > $maxLength) {
            return substr($command, 0, $maxLength) . '...';
        }
        return $command;
    }

    /**
     * Apply automatic fix by converting backticks to shell_exec().
     *
     * @param File   $phpcsFile The file being processed.
     * @param int    $opener    The opening backtick position.
     * @param int    $closer    The closing backtick position.
     * @param string $content   The content between backticks.
     *
     * @return void
     */
    private function applyAutoFix(File $phpcsFile, $opener, $closer, $content)
    {
        $phpcsFile->fixer->beginChangeset();
        
        // Replace opening backtick with shell_exec('
        $phpcsFile->fixer->replaceToken($opener, "shell_exec('");
        
        // Escape any single quotes in the content
        $escapedContent = str_replace("'", "\\'", $content);
        
        // Replace content if it needs escaping
        if ($escapedContent !== $content) {
            for ($i = $opener + 1; $i < $closer; $i++) {
                $phpcsFile->fixer->replaceToken($i, '');
            }
            $phpcsFile->fixer->addContent($opener, $escapedContent);
        }
        
        // Replace closing backtick with ')
        $phpcsFile->fixer->replaceToken($closer, "')");
        
        $phpcsFile->fixer->endChangeset();
    }
}