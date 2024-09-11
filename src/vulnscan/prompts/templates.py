VULN_SCAN_CODE_V1 = """
Task: Perform a deep vulnerability scan for the code lines below.

File: {filename}
Programming Language: {programming_language}
Code:
{code}

Instructions:
- Focus solely on detecting vulnerabilities in the provided code lines.
- Ignore styling issues and any incomplete function definitions.
- The provided code lines are a subset and may lack complete function scope or braces.
- Do not comment on the completeness of the function, only assess the given lines for vulnerabilities.
"""

VULN_SCAN_DIFF_V1 = """
Task: Perform a deep vulnerability scan for the patch given in the unidiff format lines below.

File: {filename}
Programming Language: {programming_language}
Diff:
{code}

Instructions:
- Focus solely on detecting vulnerabilities in the provided change.
- Ignore styling issues and any incomplete function definitions.
- It should be highlighted if the changed code contains any vulnerability or not.
- Ignore things in the original code if it is changed in the patch.
"""

VULN_SCAN_CODE_V2 = """
Task: Perform a deep vulnerability scan for the code lines below.

Instructions:
- Focus solely on detecting vulnerabilities in the provided code lines.
- Ignore styling issues and any incomplete function definitions.
- The provided code lines are a subset and may lack complete function scope or braces.
- Do not comment on the completeness of the function, only assess the given lines for vulnerabilities.

{code}
"""

VULN_SCAN_CODE_V3_LABEL_DETECTION_PROMPT = """
Task: Identify potential categories of security vulnerabilities in the provided code lines.

Instructions:
1. For each line of code, determine the potential category of security vulnerabilities that might be introduced. 
2. If a line presents a risk, label it with the appropriate vulnerability category. Examples of categories include: XSS, SQLInjection, BufferOverflow, IllegalMemoryAccess, etc.
3. Return the line numbers and corresponding vulnerability categories for all identified risks.
4. Do not consider coding style, completeness, or actual vulnerability presence; focus solely on potential risks based on the given lines.
5. Assume the code lines are partial and may not include full function scope or structure. Assess only the provided lines.

{code}
"""

VULN_SCAN_CODE_V3 = """
Task: Perform a focused vulnerability scan on the provided code lines.

Instructions:
1. **Analyze Only the Given Lines:** Assess only the specific lines of code provided. Do not infer or speculate about external dependencies, packages, or code that is not explicitly included in the input.
2. **Focus on In-Code Vulnerabilities:** Identify potential security vulnerabilities directly within the provided lines. Examples include XSS, SQLInjection, BufferOverflow, IllegalMemoryAccess, and CSP issues. Do not consider missing elements (e.g., content security policy) unless their absence is evident in the given lines.
3. **Avoid External Speculation:** Do not mention vulnerabilities related to external factors not present in the code, such as package vulnerabilities, external configurations, or dependencies not shown in the code.
4. **Comprehensive Detection:** Ensure that you detect all relevant vulnerabilities within the provided code lines, including but not limited to missing Content Security Policy (CSP) headers, insecure coding practices, and direct vulnerabilities in the logic or structure of the code.
5. **Use Provided Context:** Utilize the provided line numbers and vulnerability categories to guide your analysis, but focus strictly on the content within the lines themselves.
6. Provide a detailed analysis of each vulnerable line identified, explaining the potential risk, why it is a concern, and suggesting a possible mitigation.

Provided Context:
- **Possible Vulnerable Line Numbers:** {linenos}
- **Possible Vulnerability Categories:** {labels}

Code Lines to Analyze:
{code}

"""

ARCHIVE_VULN_SCAN_CODE_V4_BLOCK_CLASSIFICATION_PROMPT = """
Task: Break down the provided code into logical, coherent functional blocks, and then classify each block with the provided and most relevant functional area labels.

Instructions:
1. First, analyze the code lines and group them into logical, coherent functional blocks based on their functionality.
2. For each block, assign the most relevant functional area tuple. If a block is relevant to multiple functional areas, assign up to three tuples, prioritizing the most significant ones.
3. Only give the relevant tuples from the ones provided below.
4. Skip lines with braces, whitespaces, newlines, or comments that do not contribute to defining a functional block.
5. Return the details in the provided tool format for each block.

Functional area labels are tuples with first item as primary_functional_area and second as secondary_functional_area:
{functional_areas}

Code Lines with line number labels:
{code}
"""

ARCHIVE_VULN_SCAN_CODE_V4_BLOCK_ISSUE_ANALYSIS_PROMPT = """
Task: Analyze the provided code blocks, tagged with relevant functional areas, to determine if any code vulnerabilities are present.

Analysis Steps:
Step 1: First go through the input possible functional issues and then verify if any of these issues are present in the associated block of code. 
Step 2: Now analyse each block of code for vulnerabilities wrt the tagged functional areas and not present in the input possibilities. 
Step 3: Indicate whether the block is vulnerable or not based on analysis in step 1 and 2. For each detected issue, provide a brief analysis explaining the potential risk, why it is a concern, and suggesting a possible mitigation.
Step 4: Return the results as per block analysis in the provided tool format.

Code Blocks:
{code_blocks}
"""

VULN_SCAN_CODE_V4_BLOCK_CLASSIFICATION_PROMPT = """
Task: Break down the provided code into logical, coherent functional blocks, and classify each block with the most relevant functional area labels from the provided list.

Instructions:

1. Identify Logical Functional Blocks:
- Review the provided code lines and group them into logical, coherent functional blocks based on their functionality.
- Each block should represent a self-contained set of operations or a single coherent task, reflecting the main functional purpose.
- **Avoid granular classification**—focus on capturing the functional essence of each block.

2. Ensure Functional Area Classification:
- Classify each block using the most relevant functional area tuple(s) from the provided list.
- Aim to cover the functional aspects thoroughly to facilitate deeper analysis in subsequent steps. Ensure that each block is classified in a way that highlights its core functionality, making it easier to assess its significance and potential implications.
- If a block is relevant to multiple functional areas, assign up to two tuples, ensuring that these reflect the primary functions of the block.

3. Exclude Non-Functional Code Lines:
- Skip lines such as braces, whitespace, newlines, or comments that do not contribute to defining a functional block.
- Focus only on code lines that are integral to the functionality.

Functional Area Labels: These are tuples, with the first item as the `primary_functional_area` and the second as the `sub_functional_area`. Only use the tuples provided in the list below:

{functional_areas}

Code Lines: The code lines are provided with line number labels for reference:

{code}
"""

VULN_SCAN_CODE_V4_BLOCK_ISSUE_ANALYSIS_PROMPT = """
Task: Analyze the provided code, tagged with relevant functional areas, to determine if any code vulnerabilities are present. Provide a vulnerability score associated with each detected issue.

# Analysis Steps and Instructions:

Step 1. Analyze Code Blocks for Security Vulnerabilities with respect to the Tagged Functional Areas:
- Focus **exclusively** on the provided code. Do **NOT** infer or speculate about missing code, external dependencies, or potential issues that are not explicitly shown in the provided code.
- Use the provided example issues related to the functional areas as guidance. However, only flag issues if they are **directly observable** in the provided code. If the code is partial or lacks context, do **NOT** treat the absence of information as a vulnerability.
- Evaluate the usage of functions, APIs, and data handling **as implemented in the code**. Do **NOT** speculate about how the code might be used or what it might interact with outside of the provided context.

Step 2. Apply  Constraints: Verify that the issue adheres to the following constraints:
- The issue is observed **explicitly** within the given code and **not** inferred from external dependencies, packages, modules, or libraries.
- The highlighted issue is **NOT** based on speculation about code that is **NOT** provided or discussed in the input.
- The issue is **NOT** related to the mere presence of an import or external module but is tied to the actual usage in the provided code that demonstrates a security risk.
- The issue does **NOT** involve general bad programming practices unless they present a clear, exploitable security risk.
- The issue is **NOT** a trivial recommendation or a non-issue.
- The issue does **NOT** involve missing error handling as a standalone concern unless it presents a direct security vulnerability.
- The issue is **NOT** based on missing elements (like content security policy) unless their absence is clearly evident in the provided code lines.

Step 3. Generate a Score and Brief Analysis of each issue:
- Assign a score between 1 and 10 to each issue based on the risk of causing a security incident. Lower scores indicate lower risk.
- Clearly identify if the highlighted issue is an exploitable vulnerability. If it is not exploitable or only a potential improvement, it should **NOT** be treated as a vulnerability.
- For each detected and verified issue, provide the exact code line where the issue is observed.
- Include a brief analysis explaining the potential risk, why it is a concern, and suggest possible mitigation strategies.

Step 4. Reverse Verification of Constraints and Output:
- Before finalizing and reporting any detected issue, check if any constraint is violated.
- If yes, reanalyze and reassess the issue.
- Determine whether it should still be flagged as a vulnerability based on the constraints and provided code.
- If you assign a score less than 5, carefully reassess whether the issue is genuinely exploitable or if it is more of a code hardening suggestion. Adjust the score if necessary.

Step 5. Report the Analysis:
- After verification, report the score, whether it is exploitable or not and the issue analysis in provided response format.
- Focus the analysis **ONLY** on detected issues. Do not discuss non-issues or code lines that are not vulnerable.

### Code Blocks:
{code_blocks}
"""

VULN_SCAN_CODE_V5_BLOCK_ISSUE_ANALYSIS_PROMPT = """
# Task: Analyze the provided code, tagged with relevant functional areas, to determine if any code vulnerabilities are present and provide a overall vulnerability score. 

# Code Blocks
- Consider all the code lines in the blocks below as a single, cohesive unit. They are categorized and tagged based on their functional areas and potential issues, but should be treated as one unified entity.

<--- Code lines
{code_blocks}
Code lines --->

# Analysis Steps and Instructions:

Step 1. Analyze Code Blocks for Security Vulnerabilities with respect to the Tagged Functional Areas:
- Focus **exclusively** on the provided code. Do **NOT** infer or speculate about missing code, external dependencies, or potential issues that are not explicitly shown in the provided code.
- Use the provided example issues related to the functional areas as guidance. However, only flag issues if they are **directly observable** in the provided code. If the code is partial or lacks context, do **NOT** treat the absence of information as a vulnerability.
- Evaluate the usage of functions, APIs, and data handling **as implemented in the code**. Do **NOT** speculate about how the code might be used or what it might interact with outside of the provided context.

Step 2. Apply  Constraints: Verify that the issue adheres to the following constraints:
- The issue is observed **explicitly** within the given code and **not** inferred from external dependencies, packages, modules, or libraries.
- The highlighted issue is **NOT** based on speculation about code that is **NOT** provided or discussed in the input.
- The issue is **NOT** related to the mere presence of an import or external module but is tied to the actual usage in the provided code that demonstrates a security risk.
- The issue does **NOT** involve general bad programming practices unless they present a clear, exploitable security risk.
- The issue is **NOT** a trivial recommendation or a non-issue.
- The issue does **NOT** involve missing error handling as a standalone concern unless it presents a direct security vulnerability.
- The issue is **NOT** based on missing elements (like content security policy) unless their absence is clearly evident in the provided code lines.

Step 3. Generate a Score and Brief Analysis:
- Assign a overall score between 1 and 10 for all the code blocks as one unit, based on the risk of causing a security incident. Lower scores indicate lower risk.
- Clearly identify if the highlighted issues are an exploitable vulnerability. If it is not exploitable or only a potential improvement, it should **NOT** be treated as a vulnerability.
- For each detected and verified issue, provide the exact code lines where the issue is observed.
- Include a brief analysis explaining the potential risks, why it is a concern, and suggest possible mitigation strategies.

Step 4. Reverse Verification of Constraints and Output:
- Before finalizing and reporting any detected issue, check if any constraint is violated.
- If yes, reanalyze and reassess the issue.
- Determine whether it should still be flagged as a vulnerability based on the constraints and provided code.
- If you assign a score less than 5, carefully reassess whether the issue is genuinely exploitable or if it is more of a code hardening suggestion. Adjust the score if necessary.

Step 5. Report the Analysis:
- After verification, report the score, whether the code is exploitable or not and the issue code lines analysis in provided response format.
- Focus the analysis **ONLY** on detected issues. Do not discuss non-issues or code lines that are not vulnerable.
"""
