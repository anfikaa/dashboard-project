<x-filament::widget>
    <x-filament::section heading="Severity Breakdown">
        <div class="grid gap-4">
            <div class="rounded-xl border border-danger-200 bg-danger-50 px-4 py-4 dark:border-danger-500/30 dark:bg-danger-500/10">
                <div class="text-xs font-medium uppercase tracking-[0.2em] text-danger-600 dark:text-danger-300">FAIL</div>
                <div class="mt-2 text-3xl font-semibold text-danger-700 dark:text-danger-200">{{ $fail }}</div>
                <div class="mt-1 text-sm text-danger-600 dark:text-danger-300">Critical findings that need immediate action.</div>
            </div>

            <div class="rounded-xl border border-warning-200 bg-warning-50 px-4 py-4 dark:border-warning-500/30 dark:bg-warning-500/10">
                <div class="text-xs font-medium uppercase tracking-[0.2em] text-warning-600 dark:text-warning-300">WARN</div>
                <div class="mt-2 text-3xl font-semibold text-warning-700 dark:text-warning-200">{{ $warn }}</div>
                <div class="mt-1 text-sm text-warning-600 dark:text-warning-300">Items that should be reviewed soon.</div>
            </div>

            <div class="rounded-xl border border-success-200 bg-success-50 px-4 py-4 dark:border-success-500/30 dark:bg-success-500/10">
                <div class="text-xs font-medium uppercase tracking-[0.2em] text-success-600 dark:text-success-300">PASS</div>
                <div class="mt-2 text-3xl font-semibold text-success-700 dark:text-success-200">{{ $pass }}</div>
                <div class="mt-1 text-sm text-success-600 dark:text-success-300">Checks that are currently compliant.</div>
            </div>
        </div>
    </x-filament::section>
</x-filament::widget>
